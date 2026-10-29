// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"github.com/aplane-algo/aplane/internal/racetest"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/storepaths"
	rotatingfamilyreg "github.com/aplane-algo/aplane/lsig/rotatingfamily/signerreg"
	"github.com/aplane-algo/aplane/lsig/rotatingtriplexmss/signerops"
)

// The golden stage 0 address of lsig/rotatingtriplexmss/signerops for the
// fixed seed 0..63 on genesis 0xA0...
const goldenAddress = "PQ4C2LV5LRJQLAVLQMIJFH2KKS3YR4OVAEZN52WVSC7GELBAKJHN7CVNXA"

func fixedPayload(t *testing.T) (*keys.Payload, string) {
	t.Helper()
	racetest.SkipFullTree(t)
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
	if StageOps() == nil {
		t.Fatal("no stage ops")
	}
}

// TestRegisteredStageOpsIsTheSharedInstance checks that registration hands
// the signing flow this package's one StageOps, not a copy or a wrapper: key
// generation, validation and signing share its tree cache, and the flow finds
// tree preparation through signing.RotatingTreeOps.
func TestRegisteredStageOpsIsTheSharedInstance(t *testing.T) {
	Register()
	ops, err := signing.GetRotatingStageOps(rotatingkey.RotatingTripleXmssV1)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := ops.(*signerops.StageOps); !ok || got != StageOps() {
		t.Fatalf("registered stage ops is %T, not the package's StageOps instance", ops)
	}
	if _, ok := ops.(signing.RotatingTreeOps); !ok {
		t.Fatal("registered stage ops does not implement signing.RotatingTreeOps")
	}
}

func TestKeyPayloadRoundTripsToStageZeroAddress(t *testing.T) {
	payload, address := fixedPayload(t)
	if address != goldenAddress {
		t.Fatalf("account address %s", address)
	}
	if len(payload.PublicKey) != rotatingkey.RotatingXmssStagePublicKeySize {
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
	if parsed.Category != keys.CategoryRotatingLsig || parsed.KeyType != rotatingkey.RotatingTripleXmssV1 {
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

// Every field of the stage 0 record is checked against the seed on parse:
// the tag, the public seed, the Ed25519 and Falcon keys cheaply, and the
// root whenever tree 0 is cached (fixedPayload cached it).
func TestKeyPayloadRejectsTampering(t *testing.T) {
	const tagEnd = signerops.AccountTagSize
	const falconEnd = tagEnd + 1793
	const rootEnd = falconEnd + 32
	const seedEnd = rootEnd + 32
	tests := []struct {
		name   string
		mutate func(*keys.Payload)
	}{
		{"seed", func(p *keys.Payload) { p.PrivateKey[0] ^= 1 }},
		{"genesis hash", func(p *keys.Payload) { p.GenesisHash[0] ^= 1 }},
		{"account tag", func(p *keys.Payload) { p.PublicKey[0] ^= 1 }},
		{"falcon public key", func(p *keys.Payload) { p.PublicKey[tagEnd+10] ^= 1 }},
		{"root", func(p *keys.Payload) { p.PublicKey[falconEnd] ^= 1 }},
		{"public seed", func(p *keys.Payload) { p.PublicKey[rootEnd] ^= 1 }},
		{"ed25519 public key", func(p *keys.Payload) { p.PublicKey[seedEnd] ^= 1 }},
		{"short seed", func(p *keys.Payload) { p.PrivateKey = p.PrivateKey[:32] }},
		{"short public key", func(p *keys.Payload) { p.PublicKey = p.PublicKey[:100] }},
		{"missing genesis hash", func(p *keys.Payload) { p.GenesisHash = nil }},
		{"other key type", func(p *keys.Payload) { p.KeyType = "aplane.falcon1024.v1" }},
		{"stored bytecode", func(p *keys.Payload) { p.LogicSigBytecode = []byte{0x0d} }},
		{"salt counter", func(p *keys.Payload) { p.SaltCounter = keys.SaltCounterPtr(0) }},
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
	if info.Category != keys.CategoryRotatingLsig || info.KeyType != rotatingkey.RotatingTripleXmssV1 {
		t.Fatalf("scan category %q key type %q", info.Category, info.KeyType)
	}
	if info.PublicKeyHex != "" {
		t.Fatal("scan exposed stage 0 public keys")
	}
	profile := info.LogicSigResources
	if profile == nil || profile.Default == nil {
		t.Fatal("scan reported no resource profile")
	}
	if profile.ProgramBytes != rotatingkey.RotatingXmssMaxProgramBytes ||
		profile.Default.ArgumentBytes != rotatingkey.RotatingXmssMaxArgumentBytes ||
		profile.Default.MaxOpcodeCost != rotatingkey.RotatingXmssMaxOpcodeCost {
		t.Fatalf("resource profile %+v %+v", profile, *profile.Default)
	}
}

func TestGeneratorCreatesAccountBoundToNetwork(t *testing.T) {
	racetest.SkipFullTree(t) // generating an account builds tree 0
	Register()
	paths := genstoretest.MintFirst(t, storepaths.NewPaths(t.TempDir()))
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatal(err)
	}
	kr := cryptotest.Keyring(t, masterKey)
	gen, err := keygen.GetGenerator(rotatingkey.RotatingTripleXmssV1)
	if err != nil {
		t.Fatal(err)
	}
	if gen.RoutingFamily() != rotatingkey.RotatingTripleXmssFamily {
		t.Fatalf("routing family %q", gen.RoutingFamily())
	}
	if _, err := gen.GenerateRandom(context.Background(), paths, kr, rotatingkey.RotatingTripleXmssV1, map[string]string{}); !errors.Is(err, keygen.ErrInvalidParams) {
		t.Fatalf("missing network: err = %v", err)
	}
	result, err := gen.GenerateRandom(context.Background(), paths, kr, rotatingkey.RotatingTripleXmssV1, map[string]string{"network": "testnet"})
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyType != rotatingkey.RotatingTripleXmssV1 || len(strings.Fields(result.Mnemonic)) != 24 {
		t.Fatalf("result = %+v", result)
	}
	scanned, err := keys.ScanKeysDirectoryWithKeyring(paths, kr)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := scanned[result.Address]; !ok {
		t.Fatalf("generated account %s not found by scan", result.Address)
	}
	// The same mnemonic on another network is a different account: its
	// tree seeds differ, so its root and every stage address do.
	seed, err := rotatinghybrid.SeedFromMnemonic(strings.Fields(result.Mnemonic))
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Zero()
	testnetGenesis, err := rotatingfamilyreg.GenesisHashParameter(map[string]string{"network": "testnet"})
	if err != nil {
		t.Fatal(err)
	}
	var otherGenesis [32]byte
	otherGenesis[0] = 1
	d1, err := signerops.NewDeriver(&seed, testnetGenesis)
	if err != nil {
		t.Fatal(err)
	}
	defer d1.Zero()
	d2, err := signerops.NewDeriver(&seed, otherGenesis)
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Zero()
	s1, err := signerops.TreeSeeds(d1, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Zero()
	s2, err := signerops.TreeSeeds(d2, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Zero()
	if s1.PubSeed == s2.PubSeed || s1.SKSeed == s2.SKSeed {
		t.Fatal("the same mnemonic has the same tree on two networks")
	}
	if _, err := gen.GenerateFromSeed(context.Background(), paths, seed[:], kr, rotatingkey.RotatingTripleXmssV1, nil); err == nil {
		t.Fatal("raw seed generation accepted")
	}
}
