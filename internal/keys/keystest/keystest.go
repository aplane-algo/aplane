// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package keystest builds canonical key payload fixtures for tests. It is the
// single owner of the New*Payload -> MarshalPayload fixture pattern, so a
// payload schema change is one edit here instead of one per test package.
package keystest

import (
	"crypto/ed25519"
	"testing"

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

// SentryComponentEd25519KeyJSON returns a deterministic canonical sentry
// ed25519 component payload (seed is 32 bytes of seedFill) and its Sentry Key
// ID selector.
func SentryComponentEd25519KeyJSON(t testing.TB, seedFill byte) (componentKey string, keyJSON []byte) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedFill
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	componentKey, err := keytypes.ComponentKeySelector(keytypes.SentryComponentEd25519V1, publicKey)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}
	payload := keys.NewComponentPayload(keytypes.SentryComponentEd25519V1, publicKey, privateKey)
	defer payload.ZeroSecrets()
	return componentKey, marshal(t, payload, "component")
}

func marshal(t testing.TB, payload *keys.Payload, kind string) []byte {
	t.Helper()
	keyJSON, err := keys.MarshalPayload(payload)
	if err != nil {
		t.Fatalf("MarshalPayload(%s) error = %v", kind, err)
	}
	return keyJSON
}
