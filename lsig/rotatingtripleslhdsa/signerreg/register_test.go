// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/lsig/rotatingtripleslhdsa/signerops"
)

func fixedPayload(t *testing.T) (*keys.Payload, string) {
	t.Helper()
	Register()
	var seed rotatinghybrid.Seed
	for i := range seed {
		seed[i] = byte(i)
	}
	defer seed.Zero()
	var genesisHash [rotatinghybrid.GenesisHashSize]byte
	for i := range genesisHash {
		genesisHash[i] = byte(0xA0 + i)
	}
	payload, address, err := NewKeyPayload(&seed, genesisHash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(payload.ZeroSecrets)
	return payload, address
}

func TestRegisterIsIdempotent(t *testing.T) {
	Register()
	Register()
}

func TestKeyPayloadRoundTripsToStageZeroAddress(t *testing.T) {
	payload, address := fixedPayload(t)
	if address != "T3DTKVRZHFKYNIRHXN5RWY6SCXXCI7GG3TPJPB7FIFVXG2HPARBVYQM5UM" {
		t.Fatalf("stage zero address %s", address)
	}
	if len(payload.PublicKey) != rotatingkey.RotatingSlhdsaStagePublicKeySize {
		t.Fatalf("stage 0 record is %d bytes", len(payload.PublicKey))
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
	if parsed.Category != keys.CategoryRotatingLsig || parsed.KeyType != rotatingkey.RotatingTripleSlhdsaV1 {
		t.Fatalf("parsed category %q key type %q", parsed.Category, parsed.KeyType)
	}
	selector, err := parsed.Selector()
	if err != nil {
		t.Fatal(err)
	}
	if selector != address {
		t.Fatalf("selector %s, want %s", selector, address)
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
		{"SLH seed", func(p *keys.Payload) { p.PublicKey[3] ^= 1 }},
		{"falcon public key", func(p *keys.Payload) { p.PublicKey[40] ^= 1 }},
		{"SLH root", func(p *keys.Payload) { p.PublicKey[19] ^= 1 }},
		{"ed25519 public key", func(p *keys.Payload) { p.PublicKey[len(p.PublicKey)-1] ^= 1 }},
		{"short seed", func(p *keys.Payload) { p.PrivateKey = p.PrivateKey[:32] }},
		{"short public key", func(p *keys.Payload) { p.PublicKey = make([]byte, rotatingkey.RotatingSlhdsaStagePublicKeySize-1) }},
		{"long public key", func(p *keys.Payload) { p.PublicKey = make([]byte, rotatingkey.RotatingSlhdsaStagePublicKeySize+1) }},
		{"missing genesis hash", func(p *keys.Payload) { p.GenesisHash = nil }},
		{"retired rotating type", func(p *keys.Payload) { p.KeyType = "aplane.rotating-hybrid.v1" }},
		{"stored bytecode", func(p *keys.Payload) { p.LogicSigBytecode = []byte{0x0d} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, _ := fixedPayload(t)
			tt.mutate(payload)
			if _, err := keys.MarshalPayload(payload); !errors.Is(err, keys.ErrIncompatibleKeyFormat) {
				t.Fatalf("MarshalPayload error = %v, want incompatible key format", err)
			}
		})
	}
}

func TestScanHidesStageKeysAndReportsConstantProfile(t *testing.T) {
	payload, address := fixedPayload(t)
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
	if info.Category != keys.CategoryRotatingLsig || info.KeyType != rotatingkey.RotatingTripleSlhdsaV1 {
		t.Fatalf("scan category %q key type %q", info.Category, info.KeyType)
	}
	if info.PublicKeyHex != "" {
		t.Fatal("scan exposed stage 0 public keys")
	}
	profile := info.LogicSigResources
	if profile == nil || profile.Default == nil {
		t.Fatal("scan reported no resource profile")
	}
	if profile.ProgramBytes != rotatingkey.RotatingSlhdsaMaxProgramBytes ||
		profile.Default.ArgumentBytes != rotatingkey.RotatingSlhdsaMaxArgumentBytes ||
		profile.Default.MaxOpcodeCost != rotatingkey.RotatingSlhdsaMaxOpcodeCost {
		t.Fatalf("resource profile %+v %+v", profile, *profile.Default)
	}
}

func TestGeneratorCreatesAccountBoundToNetwork(t *testing.T) {
	Register()
	paths := genstoretest.MintFirst(t, storepaths.NewPaths(t.TempDir()))
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatal(err)
	}
	kr := cryptotest.Keyring(t, masterKey)
	gen, err := keygen.GetGenerator(rotatingkey.RotatingTripleSlhdsaV1)
	if err != nil {
		t.Fatal(err)
	}
	if gen.RoutingFamily() != rotatingkey.RotatingTripleSlhdsaFamily {
		t.Fatalf("routing family %q", gen.RoutingFamily())
	}
	if _, err := gen.GenerateRandom(context.Background(), paths, kr, rotatingkey.RotatingTripleSlhdsaV1, map[string]string{}); !errors.Is(err, keygen.ErrInvalidParams) {
		t.Fatalf("missing network: err = %v", err)
	}
	result, err := gen.GenerateRandom(context.Background(), paths, kr, rotatingkey.RotatingTripleSlhdsaV1, map[string]string{"network": "testnet"})
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyType != rotatingkey.RotatingTripleSlhdsaV1 || len(strings.Fields(result.Mnemonic)) != 24 {
		t.Fatalf("unexpected generation result type %q or mnemonic length", result.KeyType)
	}
	scanned, err := keys.ScanKeysDirectoryWithKeyring(paths, kr)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := scanned[result.Address]; !ok {
		t.Fatalf("generated account %s not found by scan", result.Address)
	}
	// The same mnemonic on another network is a different account.
	seed, err := rotatinghybrid.SeedFromMnemonic(strings.Fields(result.Mnemonic))
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Zero()
	var otherGenesis [32]byte
	otherGenesis[0] = 1
	d, err := signerops.NewDeriver(&seed, otherGenesis)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Zero()
	stageKeys, program, err := signerops.DeriveStage(d, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer stageKeys.Zero()
	if program.Address.String() == result.Address {
		t.Fatal("account address does not depend on the network")
	}
	if _, err := gen.GenerateRandom(context.Background(), paths, kr, "aplane.rotating-hybrid.v1", map[string]string{"network": "testnet"}); err == nil {
		t.Fatal("generator accepted a retired rotating key type")
	}
}

func TestGenesisHashIsRotatingOnly(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := keys.NewEd25519Payload(publicKey, privateKey)
	defer payload.ZeroSecrets()
	payload.GenesisHash = make([]byte, 32)
	if _, err := keys.MarshalPayload(payload); err == nil || !strings.Contains(err.Error(), "genesis_hash") {
		t.Fatalf("ed25519 payload with genesis_hash: err = %v", err)
	}
}
