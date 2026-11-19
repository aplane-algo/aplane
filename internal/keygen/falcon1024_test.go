// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keygen

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/algorand/falcon"
	algomnemonic "github.com/algorand/go-algorand-sdk/v2/mnemonic"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/keys"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

var registerNativeValidatorForKeygenTestOnce sync.Once

func registerNativeValidatorForKeygenTest() {
	registerNativeValidatorForKeygenTestOnce.Do(func() {
		keys.RegisterNativePQKeyPairValidator(nativefalcon.Scheme, func(publicKey, privateKey, recoveryEntropy []byte) error {
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
}

// GenerateRandom keeps the recovery entropy in the key file, and the phrase
// an export derives from it recovers the same account.
func TestNativeFalconGenerateRandomKeepsRecoverableEntropy(t *testing.T) {
	registerNativeValidatorForKeygenTest()
	paths, cleanup := setupTestKeystore(t)
	defer cleanup()
	gen := &NativeFalconGenerator{}
	kr := cryptotest.Keyring(t, testMasterKey)
	result, err := gen.GenerateRandom(context.Background(), paths, kr, nativefalcon.KeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := keys.ReadDecryptedKeyJSONWithKeyring(result.KeyFiles.PrivateFile, kr)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := keys.ParsePayload(data)
	if err != nil {
		t.Fatal(err)
	}
	defer payload.ZeroSecrets()
	words, err := algomnemonic.FromKey(payload.RecoveryEntropy)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(strings.Fields(words)); got != nativefalcon.MnemonicWordCount {
		t.Fatalf("mnemonic words = %d, want %d", got, nativefalcon.MnemonicWordCount)
	}
	otherPaths, otherCleanup := setupTestKeystore(t)
	defer otherCleanup()
	recovered, err := gen.GenerateFromMnemonic(context.Background(), otherPaths, words, kr, nativefalcon.KeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Address != result.Address {
		t.Fatalf("recovered %s from the stored entropy, generated %s", recovered.Address, result.Address)
	}
}
