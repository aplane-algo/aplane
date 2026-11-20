// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package keystest builds canonical key payload fixtures for tests. It is the
// single owner of the New*Payload -> MarshalPayload fixture pattern, so a
// payload schema change is one edit here instead of one per test package. It
// also holds the key-file paths and the key scan that tests reach for.
package keystest

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/lsigsalt/lsigsalttest"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	nativeops "github.com/aplane-algo/aplane/internal/signing/falcon1024/signerops"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"

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
// given key type and unsalted bytecode.
func GenericLSigKeyJSON(t testing.TB, keyType string, bytecode []byte, params map[string]string, tealSource string) []byte {
	t.Helper()
	payload := keys.NewGenericLSigPayload(keyType, params, bytecode, tealSource, nil, "")
	return marshal(t, payload, "generic_lsig")
}

// RetiredSaltCounterLSigKeyJSON returns an unsalted generic_lsig key payload
// as releases before salt_counter was retired wrote it, carrying
// "salt_counter": 0, and its address. The current parser refuses it.
func RetiredSaltCounterLSigKeyJSON(t testing.TB) (address string, keyJSON []byte) {
	t.Helper()
	program := lsigsalttest.OffCurve(t, []byte{0x06, 0x81, 0x01, 0x00}, 3)
	var object map[string]json.RawMessage
	if err := json.Unmarshal(GenericLSigKeyJSON(t, "test.generic.v1", program.Bytecode, nil, ""), &object); err != nil {
		t.Fatal(err)
	}
	object["salt_counter"] = json.RawMessage("0")
	keyJSON, err := json.MarshalIndent(object, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return program.Address.String(), keyJSON
}

// DSALSigKeyJSON returns a canonical dsa_lsig key payload for the given key
// material and unsalted bytecode.
func DSALSigKeyJSON(t testing.TB, keyType, baseKeyType string, publicKey, privateKey, bytecode []byte) []byte {
	t.Helper()
	payload := keys.NewDSALSigPayload(keyType, baseKeyType, publicKey, privateKey, nil, bytecode, "", nil, "")
	defer payload.ZeroSecrets()
	return marshal(t, payload, "dsa_lsig")
}

// CosignerComponentFalcon1024KeyJSON returns a deterministic canonical Falcon
// cosigner component payload and its Witness Key ID selector.
func CosignerComponentFalcon1024KeyJSON(t testing.TB, seedFill byte) (componentKey string, keyJSON []byte) {
	t.Helper()
	registerFalconComponentValidator.Do(func() {
		witness.RegisterPairValidator(witness.Falcon1024V1, validateFalconComponentPair)
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
	componentKey, err = witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatalf("witness.ID() error = %v", err)
	}
	payload := keys.NewWitnessPayload(witness.Falcon1024V1, publicKey, privateKey)
	defer payload.ZeroSecrets()
	return componentKey, marshal(t, payload, "witness")
}

// NativeFalconKeyJSON returns the canonical native Falcon key payload the
// writers produce for entropy, with valid_rekey_target set as they set it,
// and its address. The caller registers the native Falcon signer.
func NativeFalconKeyJSON(t testing.TB, entropy []byte) (address string, keyJSON []byte) {
	t.Helper()
	publicKey, privateKey, err := nativeops.DeriveKeyPair(entropy)
	if err != nil {
		t.Fatalf("DeriveKeyPair() error = %v", err)
	}
	defer crypto.ZeroBytes(privateKey[:])
	_, derived, err := keys.NativePQAddress(nativefalcon.KeyType, publicKey[:])
	if err != nil {
		t.Fatalf("NativePQAddress() error = %v", err)
	}
	payload := keys.NewNativeFalconPayload(publicKey[:], privateKey[:], entropy)
	defer payload.ZeroSecrets()
	payload.ValidRekeyTarget = true
	return derived.String(), marshal(t, payload, "native_pq")
}

// PreChangeNativeFalconKeyJSON returns keyJSON, a canonical native Falcon
// payload, as writers wrote it before key files dropped pq_scheme and
// pq_address_salt: format_version 2 and both fields after the key material.
// With recovery false it is a format 1 file from before native Falcon kept
// recovery entropy.
func PreChangeNativeFalconKeyJSON(t testing.TB, keyJSON []byte, recovery bool) []byte {
	t.Helper()
	var fields struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(keyJSON, &fields); err != nil {
		t.Fatalf("decode native Falcon payload: %v", err)
	}
	publicKey, err := hex.DecodeString(fields.PublicKey)
	if err != nil {
		t.Fatalf("decode native Falcon public key: %v", err)
	}
	salt, _, err := keys.NativePQAddress(nativefalcon.KeyType, publicKey)
	if err != nil {
		t.Fatalf("NativePQAddress() error = %v", err)
	}
	lines := strings.Split(string(keyJSON), "\n")
	out := make([]string, 0, len(lines)+2)
	inserted := slices.ContainsFunc(lines, func(line string) bool { return strings.HasPrefix(line, `  "pq_scheme": `) })
	for _, line := range lines {
		if !inserted && (strings.HasPrefix(line, `  "valid_rekey_target": `) || strings.HasPrefix(line, `  "created_at": `)) {
			out = append(out, `  "pq_scheme": "f1",`, fmt.Sprintf(`  "pq_address_salt": %d,`, salt))
			inserted = true
		}
		if !recovery && strings.HasPrefix(line, `  "recovery_entropy": `) {
			continue
		}
		if recovery && line == `  "format_version": 1,` {
			line = `  "format_version": 2,`
		}
		out = append(out, line)
	}
	if !inserted {
		t.Fatal("native Falcon payload has no created_at line")
	}
	return []byte(strings.Join(out, "\n"))
}

var registerFalconComponentValidator sync.Once

func validateFalconComponentPair(publicKey, privateKey []byte) error {
	if len(publicKey) != witness.Falcon1024PublicKeySize {
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
		return fmt.Errorf("cosigner public key does not match private key")
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

// AccountKeyFilePath is the account credential path for an address in a
// generation.
func AccountKeyFilePath(active storepaths.GenPaths, address string) string {
	return filepath.Join(active.KeysDir(), address+keys.AccountKeyExtension)
}

// CosignerCredentialFilePath is the cosigner credential path for a Witness
// Key ID in a generation.
func CosignerCredentialFilePath(active storepaths.GenPaths, witnessKeyID string) string {
	return filepath.Join(active.KeysDir(), witnessKeyID+keys.CosignerCredentialExtension)
}

// ScanKeys scans the bound generation's keys directory with kr and returns
// the keys it accepted, failing the test on a scan error.
func ScanKeys(t testing.TB, paths storepaths.Paths, kr *crypto.Keyring) map[string]keys.KeyScanInfo {
	t.Helper()
	active, err := genstore.Resolve(paths)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	report, err := keys.ScanKeysDirectory(active, kr, nil)
	if err != nil {
		t.Fatalf("ScanKeysDirectory() error = %v", err)
	}
	return report.Keys
}
