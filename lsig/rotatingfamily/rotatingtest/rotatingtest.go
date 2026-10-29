// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package rotatingtest is the contract every rotating key type meets: what
// its registration, key file codec, generator and stage operations must do,
// checked through the interfaces the signer uses. Each key type's tests call
// Run with its Scheme and keep only the tests particular to it, such as its
// golden vectors and its stored-payload fixture.
package rotatingtest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/storepaths"
	rotatingfamilyreg "github.com/aplane-algo/aplane/lsig/rotatingfamily/signerreg"
	"github.com/aplane-algo/aplane/lsig/rotatingfamily/stageprog"
)

// Scheme describes one rotating key type to the contract suite.
type Scheme struct {
	KeyType string
	Family  string

	// Register is the key type's registration, and NewKeyPayload its
	// payload builder.
	Register      func()
	NewKeyPayload func(*rotatinghybrid.Seed, [rotatinghybrid.GenesisHashSize]byte) (*keys.Payload, string, error)

	// GoldenAddress is the account address of FixedSeed on FixedGenesis.
	GoldenAddress string

	// StageOps is the value registration must install, compared with ==,
	// and TreeOps reports that it also implements signing.RotatingTreeOps.
	StageOps signing.RotatingStageOps
	TreeOps  bool

	// Leaf is the leaf index SignStage is given for a stage, or nil for a
	// key type whose stage holds one key.
	Leaf func(stage uint64) uint32

	// Verify parses a signing program and checks args over message against
	// the keys the program embeds, as the AVM program will.
	Verify func(program, message []byte, args [][]byte) error

	// RecordFields maps each field of the stage 0 record to the offset of
	// one byte inside it.
	RecordFields map[string]int

	// CachedFields are record fields the codec compares only while a cache
	// holds what they derive from. Cold empties that cache for a key, and
	// CacheSize reports how much the cache holds. A key type with no such
	// fields leaves all three empty.
	CachedFields []string
	Cold         func(t *testing.T, key *signing.RotatingKeyMaterial)
	CacheSize    func() int

	// SkipSlow, when set, skips the suite where building the key type's
	// keys is too slow, such as XMSS trees under the race detector.
	SkipSlow func(testing.TB)
}

// FixedSeed and FixedGenesis are the seed 0..63 on genesis 0xA0.., which every
// rotating key type's golden vectors use.
func FixedSeed() rotatinghybrid.Seed {
	var seed rotatinghybrid.Seed
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

func FixedGenesis() [rotatinghybrid.GenesisHashSize]byte {
	var genesis [rotatinghybrid.GenesisHashSize]byte
	for i := range genesis {
		genesis[i] = byte(0xA0 + i)
	}
	return genesis
}

// FixedPayload is s's key payload for FixedSeed on FixedGenesis. It is zeroed
// when the test ends.
func FixedPayload(t *testing.T, s Scheme) (*keys.Payload, string) {
	t.Helper()
	s.Register()
	seed := FixedSeed()
	defer seed.Zero()
	payload, address, err := s.NewKeyPayload(&seed, FixedGenesis())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(payload.ZeroSecrets)
	return payload, address
}

func fixedKeyMaterial() *signing.RotatingKeyMaterial {
	seed, genesis := FixedSeed(), FixedGenesis()
	return &signing.RotatingKeyMaterial{Seed: seed[:], GenesisHash: genesis[:]}
}

func testMessage(label string) []byte {
	sum := sha256.Sum256([]byte("rotatingtest " + label))
	return sum[:]
}

// Run runs the contract suite against s.
func Run(t *testing.T, s Scheme) {
	if s.SkipSlow != nil {
		s.SkipSlow(t)
	}
	t.Run("registration", func(t *testing.T) { testRegistration(t, s) })
	t.Run("payload round trip", func(t *testing.T) { testPayloadRoundTrip(t, s) })
	t.Run("tampering", func(t *testing.T) { testTampering(t, s) })
	t.Run("scan", func(t *testing.T) { testScan(t, s) })
	t.Run("generator", func(t *testing.T) { testGenerator(t, s) })
	t.Run("stage ops", func(t *testing.T) { testStageOps(t, s) })
	t.Run("network binding", func(t *testing.T) { testNetworkBinding(t, s) })
	t.Run("every argument is checked", func(t *testing.T) { testEveryArgumentIsChecked(t, s) })
}

// testRegistration checks that registering twice is harmless and that the
// signing flow finds the key type's own stage ops, not a copy or a wrapper.
func testRegistration(t *testing.T, s Scheme) {
	s.Register()
	s.Register()
	ops, err := signing.GetRotatingStageOps(s.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	if ops != s.StageOps {
		t.Fatalf("registered stage ops %T is not the key type's own value", ops)
	}
	if _, ok := ops.(signing.RotatingTreeOps); ok != s.TreeOps {
		t.Fatalf("registered stage ops implements signing.RotatingTreeOps: %v, want %v", ok, s.TreeOps)
	}
	gen, err := keygen.GetGenerator(s.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	if gen.RoutingFamily() != s.Family {
		t.Fatalf("generator routing family %q, want %q", gen.RoutingFamily(), s.Family)
	}
}

func testPayloadRoundTrip(t *testing.T, s Scheme) {
	payload, address := FixedPayload(t, s)
	if address != s.GoldenAddress {
		t.Fatalf("account address %s, want %s", address, s.GoldenAddress)
	}
	profile, ok := rotatingkey.Lookup(s.KeyType)
	if !ok {
		t.Fatalf("no rotating profile for %s", s.KeyType)
	}
	if len(payload.PublicKey) != profile.StagePublicKeySize {
		t.Fatalf("stage 0 record is %d bytes, profile says %d", len(payload.PublicKey), profile.StagePublicKeySize)
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
	if parsed.Category != keys.CategoryRotatingLsig || parsed.KeyType != s.KeyType {
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

// testTampering checks that every field of the payload and of the stage 0
// record is checked against the seed. A cached field is checked only while
// its cache is warm: with a cold cache the codec accepts it without building
// what it derives from.
func testTampering(t *testing.T, s Scheme) {
	refused := func(t *testing.T, mutate func(*keys.Payload)) {
		t.Helper()
		payload, _ := FixedPayload(t, s)
		mutate(payload)
		if _, err := keys.MarshalPayload(payload); !errors.Is(err, keys.ErrIncompatibleKeyFormat) {
			t.Fatalf("MarshalPayload error = %v, want incompatible key format", err)
		}
	}
	profile, _ := rotatingkey.Lookup(s.KeyType)
	for name, mutate := range map[string]func(*keys.Payload){
		"seed":                  func(p *keys.Payload) { p.PrivateKey[0] ^= 1 },
		"genesis hash":          func(p *keys.Payload) { p.GenesisHash[0] ^= 1 },
		"short seed":            func(p *keys.Payload) { p.PrivateKey = p.PrivateKey[:32] },
		"short public key":      func(p *keys.Payload) { p.PublicKey = make([]byte, profile.StagePublicKeySize-1) },
		"long public key":       func(p *keys.Payload) { p.PublicKey = make([]byte, profile.StagePublicKeySize+1) },
		"missing genesis hash":  func(p *keys.Payload) { p.GenesisHash = nil },
		"retired rotating type": func(p *keys.Payload) { p.KeyType = "aplane.rotating-hybrid.v1" },
		"other key type":        func(p *keys.Payload) { p.KeyType = "aplane.falcon1024.v1" },
		"stored bytecode":       func(p *keys.Payload) { p.LogicSigBytecode = []byte{0x0d} },
		"salt counter":          func(p *keys.Payload) { p.SaltCounter = keys.SaltCounterPtr(0) },
	} {
		t.Run(name, func(t *testing.T) { refused(t, mutate) })
	}
	cached := make(map[string]bool, len(s.CachedFields))
	for _, name := range s.CachedFields {
		if _, ok := s.RecordFields[name]; !ok {
			t.Fatalf("cached field %q is not a record field", name)
		}
		cached[name] = true
	}
	for name, offset := range s.RecordFields {
		flip := func(p *keys.Payload) { p.PublicKey[offset] ^= 1 }
		t.Run(name, func(t *testing.T) { refused(t, flip) })
		if !cached[name] {
			continue
		}
		t.Run(name+" with a cold cache", func(t *testing.T) {
			payload, _ := FixedPayload(t, s)
			s.Cold(t, fixedKeyMaterial())
			before := s.CacheSize()
			flip(payload)
			if _, err := keys.MarshalPayload(payload); err != nil {
				t.Fatalf("with a cold cache the codec checked %s: %v", name, err)
			}
			if after := s.CacheSize(); after != before {
				t.Fatalf("validation filled the cache: %d entries, then %d", before, after)
			}
		})
	}
}

// testScan checks that a stored account is listed without its stage 0 public
// keys and with the key type's constant resource profile.
func testScan(t *testing.T, s Scheme) {
	payload, address := FixedPayload(t, s)
	paths, kr := newStore(t)
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
	if info.Category != keys.CategoryRotatingLsig || info.KeyType != s.KeyType {
		t.Fatalf("scan category %q key type %q", info.Category, info.KeyType)
	}
	if info.PublicKeyHex != "" {
		t.Fatal("scan exposed stage 0 public keys")
	}
	resources := info.LogicSigResources
	if resources == nil || resources.Default == nil {
		t.Fatal("scan reported no resource profile")
	}
	profile, _ := rotatingkey.Lookup(s.KeyType)
	if resources.ProgramBytes != uint64(profile.MaxProgramBytes) ||
		resources.Default.ArgumentBytes != uint64(profile.MaxArgumentBytes) ||
		resources.Default.MaxOpcodeCost != uint64(profile.MaxOpcodeCost) {
		t.Fatalf("resource profile %+v %+v, rotating profile %+v", resources, *resources.Default, profile)
	}
}

// testGenerator checks that the generator needs the network parameter, makes
// an account on that network from a fresh 24-word mnemonic, and refuses the
// ways of generating a rotating account it does not support.
func testGenerator(t *testing.T, s Scheme) {
	s.Register()
	paths, kr := newStore(t)
	gen, err := keygen.GetGenerator(s.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := gen.GenerateRandom(ctx, paths, kr, s.KeyType, map[string]string{}); !errors.Is(err, keygen.ErrInvalidParams) {
		t.Fatalf("missing network: err = %v", err)
	}
	result, err := gen.GenerateRandom(ctx, paths, kr, s.KeyType, map[string]string{"network": "testnet"})
	if err != nil {
		t.Fatal(err)
	}
	words := strings.Fields(result.Mnemonic)
	if result.KeyType != s.KeyType || len(words) != 24 {
		t.Fatalf("generated key type %q with a %d-word mnemonic", result.KeyType, len(words))
	}
	scanned, err := keys.ScanKeysDirectoryWithKeyring(paths, kr)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := scanned[result.Address]; !ok {
		t.Fatalf("generated account %s not found by scan", result.Address)
	}
	seed, err := rotatinghybrid.SeedFromMnemonic(words)
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Zero()
	testnet, err := rotatingfamilyreg.GenesisHashParameter(map[string]string{"network": "testnet"})
	if err != nil {
		t.Fatal(err)
	}
	payload, address, err := s.NewKeyPayload(&seed, testnet)
	if err != nil {
		t.Fatal(err)
	}
	payload.ZeroSecrets()
	if address != result.Address {
		t.Fatalf("generated account %s is not the mnemonic's account on testnet, %s", result.Address, address)
	}
	if _, err := gen.GenerateRandom(ctx, paths, kr, "aplane.rotating-hybrid.v1", map[string]string{"network": "testnet"}); err == nil {
		t.Fatal("generator accepted a retired rotating key type")
	}
	if _, err := gen.GenerateFromSeed(ctx, paths, seed[:], kr, s.KeyType, nil); err == nil {
		t.Fatal("generation from a raw seed accepted")
	}
	if _, err := gen.GenerateFromMnemonic(ctx, paths, result.Mnemonic, kr, s.KeyType, map[string]string{"network": "testnet"}); err == nil {
		t.Fatal("generation from a mnemonic accepted")
	}
}

// testStageOps checks the registered stage ops through key material: stage
// addresses, the open test, and a signature that names its stage's program,
// verifies against it and fits the key type's resource profile.
func testStageOps(t *testing.T, s Scheme) {
	s.Register()
	ops, err := signing.GetRotatingStageOps(s.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	key := fixedKeyMaterial()
	a0, err := ops.StageAddress(key, 0)
	if err != nil {
		t.Fatal(err)
	}
	a1, err := ops.StageAddress(key, 1)
	if err != nil {
		t.Fatal(err)
	}
	if a0.String() != s.GoldenAddress {
		t.Fatalf("stage 0 address %s, want the account address %s", a0, s.GoldenAddress)
	}
	if a0 == a1 {
		t.Fatal("stages 0 and 1 share an address")
	}
	if err := ops.CheckStageOpens(key, 1); err != nil {
		t.Fatal(err)
	}
	msg := testMessage("stage ops")
	sig, err := ops.SignStage(key, 1, s.leaf(1), msg)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := stageprog.Address(sig.Program); err != nil || got != a1 {
		t.Fatalf("signing program's address %s (%v), want stage 1's %s", got, err, a1)
	}
	if err := s.Verify(sig.Program, msg, sig.Args); err != nil {
		t.Fatal(err)
	}
	profile, _ := rotatingkey.Lookup(s.KeyType)
	total := 0
	for _, arg := range sig.Args {
		total += len(arg)
	}
	if total > profile.MaxArgumentBytes || len(sig.Program) > profile.MaxProgramBytes {
		t.Fatalf("arguments %d bytes and program %d bytes exceed the profile's %d and %d", total, len(sig.Program), profile.MaxArgumentBytes, profile.MaxProgramBytes)
	}
	if _, err := ops.SignStage(&signing.RotatingKeyMaterial{Seed: key.Seed[:5], GenesisHash: key.GenesisHash}, 1, s.leaf(1), msg); err == nil {
		t.Fatal("short seed accepted")
	}
	if _, err := ops.SignStage(key, 1, s.leaf(1), msg[:31]); err == nil {
		t.Fatal("a 31-byte message was signed")
	}
}

// testNetworkBinding checks that the same seed is a different account on
// another network.
func testNetworkBinding(t *testing.T, s Scheme) {
	s.Register()
	ops, err := signing.GetRotatingStageOps(s.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	key := fixedKeyMaterial()
	other := &signing.RotatingKeyMaterial{Seed: key.Seed, GenesisHash: bytes.Clone(key.GenesisHash)}
	other.GenesisHash[0] ^= 1
	a, err := ops.StageAddress(key, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ops.StageAddress(other, 0)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("the same seed has the same stage 0 address on two networks")
	}
}

// testEveryArgumentIsChecked replaces each argument of a stage 1 signature
// with the same argument of a stage 0 signature over the same message, and
// checks that the result does not verify, and that a stage 0 signature does
// not verify under stage 1's program.
func testEveryArgumentIsChecked(t *testing.T, s Scheme) {
	s.Register()
	ops, err := signing.GetRotatingStageOps(s.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	key := fixedKeyMaterial()
	msg := testMessage("every argument")
	sig0, err := ops.SignStage(key, 0, s.leaf(0), msg)
	if err != nil {
		t.Fatal(err)
	}
	sig1, err := ops.SignStage(key, 1, s.leaf(1), msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig0.Args) != len(sig1.Args) {
		t.Fatalf("stages 0 and 1 have %d and %d arguments", len(sig0.Args), len(sig1.Args))
	}
	if err := s.Verify(sig1.Program, msg, sig1.Args); err != nil {
		t.Fatal(err)
	}
	if s.Verify(sig1.Program, msg, sig0.Args) == nil {
		t.Fatal("a stage 0 signature verified under stage 1's program")
	}
	other := testMessage("another message")
	if s.Verify(sig1.Program, other, sig1.Args) == nil {
		t.Fatal("a signature verified over another message")
	}
	for i := range sig1.Args {
		args := append([][]byte(nil), sig1.Args...)
		args[i] = sig0.Args[i]
		if s.Verify(sig1.Program, msg, args) == nil {
			t.Fatalf("argument %d from stage 0 verified under stage 1", i)
		}
	}
}

func (s Scheme) leaf(stage uint64) uint32 {
	if s.Leaf == nil {
		return 0
	}
	return s.Leaf(stage)
}

// newStore returns a fresh store and a fresh keyring to save key files with.
func newStore(t *testing.T) (storepaths.Paths, *crypto.Keyring) {
	t.Helper()
	paths := genstoretest.MintFirst(t, storepaths.NewPaths(t.TempDir()))
	kr, err := crypto.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kr.Zero)
	return paths, kr
}
