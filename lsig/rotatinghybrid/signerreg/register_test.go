// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

type vectorFile struct {
	Mnemonic    string `json:"mnemonic"`
	GenesisHash string `json:"genesis_hash"`
	Stages      []struct {
		Index   uint64 `json:"index"`
		Address string `json:"address"`
	} `json:"stages"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	data, err := os.ReadFile("../signerops/testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Stages) == 0 || v.Stages[0].Index != 0 || v.Stages[0].Address == "" {
		t.Fatal("vectors have no stage 0 address")
	}
	return v
}

func vectorPayload(t *testing.T) (*keys.Payload, string, vectorFile) {
	t.Helper()
	Register()
	v := loadVectors(t)
	seed, err := rotatinghybrid.SeedFromMnemonic(strings.Fields(v.Mnemonic))
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Zero()
	gh, err := base64.StdEncoding.DecodeString(v.GenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	var genesisHash [rotatinghybrid.GenesisHashSize]byte
	copy(genesisHash[:], gh)
	payload, address, err := NewKeyPayload(&seed, genesisHash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(payload.ZeroSecrets)
	return payload, address, v
}

func TestRegisterIsIdempotent(t *testing.T) {
	Register()
	Register()
}

func TestKeyPayloadRoundTripsToStageZeroAddress(t *testing.T) {
	payload, address, v := vectorPayload(t)
	if address != v.Stages[0].Address {
		t.Fatalf("account address %s, vector stage 0 %s", address, v.Stages[0].Address)
	}
	encoded, err := keys.MarshalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(encoded)
	parsed, err := keys.ParsePayload(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.ZeroSecrets()
	if parsed.Category != keys.CategoryRotatingLsig || parsed.KeyType != rotatingkey.RotatingHybridV1 {
		t.Fatalf("parsed category %q key type %q", parsed.Category, parsed.KeyType)
	}
	selector, err := parsed.Selector()
	if err != nil {
		t.Fatal(err)
	}
	if selector != v.Stages[0].Address {
		t.Fatalf("selector %s, want %s", selector, v.Stages[0].Address)
	}
	for _, field := range []string{`"lsig_bytecode"`, `"salt_counter"`, `"lsig_opcode_profile"`, `"base_key_type"`} {
		if bytes.Contains(encoded, []byte(field)) {
			t.Fatalf("rotating payload carries %s", field)
		}
	}
}

func TestKeyPayloadRejectsTampering(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*keys.Payload)
	}{
		{"seed", func(p *keys.Payload) { p.PrivateKey[0] ^= 1 }},
		{"genesis hash", func(p *keys.Payload) { p.GenesisHash[0] ^= 1 }},
		{"falcon public key", func(p *keys.Payload) { p.PublicKey[10] ^= 1 }},
		{"ed25519 public key", func(p *keys.Payload) { p.PublicKey[len(p.PublicKey)-1] ^= 1 }},
		{"short seed", func(p *keys.Payload) { p.PrivateKey = p.PrivateKey[:32] }},
		{"short public key", func(p *keys.Payload) { p.PublicKey = p.PublicKey[:100] }},
		{"missing genesis hash", func(p *keys.Payload) { p.GenesisHash = nil }},
		{"other key type", func(p *keys.Payload) { p.KeyType = "aplane.falcon1024.v1" }},
		{"stored bytecode", func(p *keys.Payload) { p.LogicSigBytecode = []byte{0x0d} }},
		{"salt counter", func(p *keys.Payload) { p.SaltCounter = keys.SaltCounterPtr(0) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, _, _ := vectorPayload(t)
			tt.mutate(payload)
			if _, err := keys.MarshalPayload(payload); !errors.Is(err, keys.ErrIncompatibleKeyFormat) {
				t.Fatalf("MarshalPayload error = %v, want incompatible key format", err)
			}
		})
	}
}

func TestGenesisHashIsRotatingOnly(t *testing.T) {
	publicKey, privateKey := ed25519Pair(t)
	payload := keys.NewEd25519Payload(publicKey, privateKey)
	defer payload.ZeroSecrets()
	payload.GenesisHash = make([]byte, 32)
	if _, err := keys.MarshalPayload(payload); err == nil || !strings.Contains(err.Error(), "genesis_hash") {
		t.Fatalf("ed25519 payload with genesis_hash: err = %v", err)
	}
}

func TestScanHidesStageKeysAndReportsConstantProfile(t *testing.T) {
	payload, address, _ := vectorPayload(t)
	paths := genstoretest.MintFirst(t, storepaths.NewPaths(t.TempDir()))
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatal(err)
	}
	kr := cryptotest.Keyring(t, masterKey)
	if _, err := keys.SavePayload(paths, payload, kr); err != nil {
		t.Fatal(err)
	}
	scanned, err := keys.ScanKeysDirectoryWithKeyring(paths, kr)
	if err != nil {
		t.Fatal(err)
	}
	info, ok := scanned[address]
	if !ok {
		t.Fatalf("scan did not report %s; got %v", address, scanned)
	}
	if info.Category != keys.CategoryRotatingLsig || info.KeyType != rotatingkey.RotatingHybridV1 {
		t.Fatalf("scan category %q key type %q", info.Category, info.KeyType)
	}
	if info.PublicKeyHex != "" {
		t.Fatal("scan exposed stage 0 public keys")
	}
	profile := info.LogicSigResources
	if profile == nil || profile.Default == nil {
		t.Fatal("scan reported no resource profile")
	}
	if profile.ProgramBytes != rotatingkey.RotatingMaxProgramBytes ||
		profile.Default.ArgumentBytes != rotatingkey.RotatingMaxArgumentBytes ||
		profile.Default.MaxOpcodeCost != rotatingkey.RotatingMaxOpcodeCost {
		t.Fatalf("resource profile %+v %+v", profile, *profile.Default)
	}
}

func ed25519Pair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, privateKey
}
