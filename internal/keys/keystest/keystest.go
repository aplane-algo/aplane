// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package keystest builds canonical key payload fixtures for tests. It is the
// single owner of the New*Payload -> MarshalPayload fixture pattern, so a
// payload schema change is one edit here instead of one per test package.
package keystest

import (
	"fmt"
	"sync"
	"testing"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"

	sdkcrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
)

// Ed25519KeyJSON returns a freshly generated canonical ed25519 key payload
// and its Algorand address.
func Ed25519KeyJSON(t testing.TB) (address string, keyJSON []byte) {
	t.Helper()
	account := sdkcrypto.GenerateAccount()
	payload := keys.NewEd25519Payload(account.PrivateKey[32:], account.PrivateKey)
	defer payload.ZeroSecrets()
	return account.Address.String(), marshal(t, payload, "ed25519")
}

// GenericLSigKeyJSON returns a canonical generic_lsig key payload for the
// given key type and salted bytecode.
func GenericLSigKeyJSON(t testing.TB, keyType string, bytecode []byte, saltCounter byte, params map[string]string, tealSource string) []byte {
	t.Helper()
	payload := keys.NewGenericLSigPayload(keyType, params, bytecode, saltCounter, tealSource, nil, "")
	return marshal(t, payload, "generic_lsig")
}

// DSALSigKeyJSON returns a canonical dsa_lsig key payload for the given key
// material and salted bytecode.
func DSALSigKeyJSON(t testing.TB, keyType, baseKeyType string, publicKey, privateKey, bytecode []byte, saltCounter byte) []byte {
	t.Helper()
	payload := keys.NewDSALSigPayload(keyType, baseKeyType, publicKey, privateKey, nil, bytecode, saltCounter, "", nil, "")
	defer payload.ZeroSecrets()
	return marshal(t, payload, "dsa_lsig")
}

// SentryComponentFalcon1024KeyJSON returns a deterministic canonical Falcon
// sentry component payload and its Sentry Key ID selector.
func SentryComponentFalcon1024KeyJSON(t testing.TB, seedFill byte) (componentKey string, keyJSON []byte) {
	t.Helper()
	registerFalconComponentValidator.Do(func() {
		keytypes.RegisterComponentPairValidator(keytypes.SentryComponentFalcon1024V1, validateFalconComponentPair)
	})
	seed := make([]byte, 48)
	for i := range seed {
		seed[i] = seedFill
	}
	keyPair, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	publicKey := append([]byte(nil), keyPair.PublicKey[:]...)
	privateKey := append([]byte(nil), keyPair.PrivateKey[:]...)
	componentKey, err = keytypes.ComponentKeySelector(keytypes.SentryComponentFalcon1024V1, publicKey)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}
	payload := keys.NewComponentPayload(keytypes.SentryComponentFalcon1024V1, publicKey, privateKey)
	defer payload.ZeroSecrets()
	return componentKey, marshal(t, payload, "component")
}

var registerFalconComponentValidator sync.Once

func validateFalconComponentPair(publicKey, privateKey []byte) error {
	if len(publicKey) != keytypes.Falcon1024PublicKeySize {
		return fmt.Errorf("invalid Falcon public key length %d", len(publicKey))
	}
	var keyPair falcongo.KeyPair
	if len(privateKey) != len(keyPair.PrivateKey) {
		return fmt.Errorf("invalid Falcon private key length %d", len(privateKey))
	}
	copy(keyPair.PublicKey[:], publicKey)
	copy(keyPair.PrivateKey[:], privateKey)
	message := []byte("APLANE_COMPONENT_KEY_TEST_V1")
	signature, err := keyPair.Sign(message)
	if err != nil {
		return err
	}
	if err := falcongo.Verify(message, signature, keyPair.PublicKey); err != nil {
		return fmt.Errorf("sentry public key does not match private key")
	}
	return nil
}

func marshal(t testing.TB, payload *keys.Payload, kind string) []byte {
	t.Helper()
	keyJSON, err := keys.MarshalPayload(payload)
	if err != nil {
		t.Fatalf("MarshalPayload(%s) error = %v", kind, err)
	}
	return keyJSON
}
