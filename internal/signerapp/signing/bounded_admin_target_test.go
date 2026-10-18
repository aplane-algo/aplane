// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	falconsignerops "github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
)

// composedTestKeyType stands for an author-written schema-version-1 composed
// template: a DSA base plus a TEAL suffix, no bounded block, not guarded.
const composedTestKeyType = "example.falcon1024-suffix.v1"

func TestAdminRekeyTargetIneligible(t *testing.T) {
	cases := []struct {
		name     string
		category string
		keyType  string
		bounded  bool
		wantWhy  string
	}{
		{"native ed25519", keys.CategoryEd25519, "ed25519", false, ""},
		{"native falcon", keys.CategoryNativePQ, "falcon1024", false, ""},
		{"plain falcon lsig", keys.CategoryDSALsig, plainFalcon1024LsigKeyType, false, ""},
		{"plain ed25519 lsig", keys.CategoryDSALsig, plainEd25519LsigKeyType, false, ""},
		{"bounded lsig", keys.CategoryDSALsig, "aplane.falcon1024-allowlist-alock.v1", true, "bounded"},
		{"guarded lsig", keys.CategoryDSALsig, "aplane.falcon1024-cosigner1024.v1", false, "guarded"},
		{"composed template", keys.CategoryDSALsig, composedTestKeyType, false, "not one of the plain"},
		{"generic lsig", keys.CategoryGenericLsig, "aplane.htlc.v1", false, "generic"},
		{"witness", keys.CategoryWitness, "aplane.witness-falcon1024.v1", false, "witness"},
		{"rotating", keys.CategoryRotatingLsig, "aplane.rotating-triple-hybrid.v1", false, "rotating"},
		{"unknown", "something", "x", false, "unsupported"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			why := adminRekeyTargetIneligible(tc.category, tc.keyType, tc.bounded)
			if tc.wantWhy == "" && why != "" {
				t.Fatalf("eligible credential refused: %s", why)
			}
			if tc.wantWhy != "" && !strings.Contains(why, tc.wantWhy) {
				t.Fatalf("reason %q does not mention %q", why, tc.wantWhy)
			}
		})
	}
}

func randomAddress(t *testing.T) types.Address {
	t.Helper()
	var addr types.Address
	if _, err := rand.Read(addr[:]); err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestCheckBoundedAdminRekeyTargetUsesSnapshot(t *testing.T) {
	bounded := randomAddress(t)
	held := randomAddress(t)
	boundedHeld := randomAddress(t)
	composedHeld := randomAddress(t)
	foreign := randomAddress(t)
	svc := &Service{Planner: &Planner{Snapshot: func() PlannerRuntimeSnapshot {
		return PlannerRuntimeSnapshot{
			KeyTypes: map[string]string{
				bounded.String():      "aplane.falcon1024-allowlist-alock.v1",
				held.String():         "ed25519",
				boundedHeld.String():  "aplane.falcon1024-allowlist-alock.v1",
				composedHeld.String(): composedTestKeyType,
			},
			KeyMetadata: map[string]PlannerKeyMetadata{
				bounded.String():      {Category: keys.CategoryDSALsig, BoundedAuthorization: &boundedmeta.Metadata{}},
				held.String():         {Category: keys.CategoryEd25519},
				boundedHeld.String():  {Category: keys.CategoryDSALsig, BoundedAuthorization: &boundedmeta.Metadata{}},
				composedHeld.String(): {Category: keys.CategoryDSALsig},
			},
		}
	}}}
	txn := func(sender, target types.Address) types.Transaction {
		return types.Transaction{Header: types.Header{Sender: sender, RekeyTo: target}}
	}
	for name, tx := range map[string]types.Transaction{
		"held ed25519 target":                 txn(bounded, held),
		"bounded account back to itself":      txn(bounded, bounded),
		"held sender under bounded authority": txn(held, held),
	} {
		if err := svc.checkBoundedAdminRekeyTarget(tx, bounded.String()); err != nil {
			t.Fatalf("%s refused: %v", name, err)
		}
	}
	for name, tx := range map[string]types.Transaction{
		"foreign target":                     txn(bounded, foreign),
		"bounded target":                     txn(bounded, boundedHeld),
		"composed template target":           txn(bounded, composedHeld),
		"unheld sender back to itself":       txn(foreign, foreign),
		"bounded sender back to its program": txn(boundedHeld, boundedHeld),
		"self-rekey of a different program":  txn(composedHeld, composedHeld),
	} {
		err := svc.checkBoundedAdminRekeyTarget(tx, bounded.String())
		if err == nil || err.Kind != ErrorBoundedAdminTargetRejected {
			t.Fatalf("%s: err = %v, want %s", name, err, ErrorBoundedAdminTargetRejected)
		}
	}
	// The check runs before policy and consults no policy flag. A planner
	// without a snapshot is a configuration error, not a refusal.
	if err := (&Service{Planner: &Planner{}}).checkBoundedAdminRekeyTarget(txn(bounded, held), bounded.String()); err == nil || err.Kind != ErrorInternal {
		t.Fatalf("missing snapshot: err = %v", err)
	}
}

// Test-only signing providers under test-only key types, so the package's
// shared provider registry never gains a real family that other tests in
// this package expect to be absent. They sign with the real primitives.
// LogicSig credentials carry the plain family as Type and the test provider
// as BaseKeyType, which is how the registry falls back for a composed key.
const (
	adminTargetTestTypeEd25519 = "test.admin-target.ed25519"
	adminTargetTestTypeFalcon  = "test.admin-target.falcon"
)

type adminTargetFakeProvider struct {
	family string
	sign   func(privateKey, message []byte) ([]byte, error)
}

func (p adminTargetFakeProvider) RoutingFamily() string { return p.family }
func (p adminTargetFakeProvider) LoadKeyMaterial(coresigning.ProviderKey) (*coresigning.KeyMaterial, error) {
	return nil, errors.New("not used")
}
func (p adminTargetFakeProvider) SignMessage(km *coresigning.KeyMaterial, message []byte) ([]byte, error) {
	privateKey, ok := km.Value.([]byte)
	if !ok {
		return nil, fmt.Errorf("unexpected key value %T", km.Value)
	}
	return p.sign(privateKey, message)
}
func (p adminTargetFakeProvider) ZeroKey(km *coresigning.KeyMaterial) {
	if privateKey, ok := km.Value.([]byte); ok {
		securecrypto.ZeroBytes(privateKey)
	}
	km.Value = nil
}

var adminTargetProvidersOnce sync.Once

func registerAdminTargetTestProviders() {
	adminTargetProvidersOnce.Do(func() {
		coresigning.Register(adminTargetFakeProvider{
			family: adminTargetTestTypeEd25519,
			sign: func(privateKey, message []byte) ([]byte, error) {
				return ed25519.Sign(ed25519.PrivateKey(privateKey), message), nil
			},
		})
		coresigning.Register(adminTargetFakeProvider{
			family: adminTargetTestTypeFalcon,
			sign: func(privateKey, message []byte) ([]byte, error) {
				return falconsignerops.New(nil).Sign(privateKey, message)
			},
		})
	})
}

type adminTargetFakeSession struct {
	keys map[string]*coresigning.KeyMaterial
}

func (f adminTargetFakeSession) GetKeyWithContext(_ context.Context, address string) (*coresigning.KeyMaterial, error) {
	km, ok := f.keys[address]
	if !ok {
		return nil, errors.New("no key found")
	}
	// Hand out a copy the way the keystore does; the caller zeroes it.
	cp := *km
	cp.PublicKey = append([]byte(nil), km.PublicKey...)
	cp.Bytecode = append([]byte(nil), km.Bytecode...)
	if privateKey, ok := km.Value.([]byte); ok {
		cp.Value = append([]byte(nil), privateKey...)
	}
	return &cp, nil
}

func ed25519TargetMaterial(t *testing.T) (types.Address, *coresigning.KeyMaterial) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var addr types.Address
	copy(addr[:], pub)
	return addr, &coresigning.KeyMaterial{
		Type:      adminTargetTestTypeEd25519,
		Category:  keys.CategoryEd25519,
		Value:     []byte(priv),
		PublicKey: append([]byte(nil), pub...),
	}
}

// randomProgram returns distinct bytes standing in for compiled LogicSig
// bytecode; only its address derivation matters here.
func randomProgram(t *testing.T) []byte {
	t.Helper()
	program := make([]byte, 40)
	if _, err := rand.Read(program); err != nil {
		t.Fatal(err)
	}
	return program
}

func falconLsigTargetMaterial(t *testing.T, keyType string) (types.Address, *coresigning.KeyMaterial) {
	t.Helper()
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := falconsignerops.New(nil).GenerateKeypair(seed)
	if err != nil {
		t.Fatal(err)
	}
	program := randomProgram(t)
	return algocrypto.AddressFromProgram(program), &coresigning.KeyMaterial{
		Type:        keyType,
		BaseKeyType: adminTargetTestTypeFalcon,
		Category:    keys.CategoryDSALsig,
		Value:       priv,
		PublicKey:   pub,
		Bytecode:    program,
	}
}

func ed25519LsigTargetMaterial(t *testing.T) (types.Address, *coresigning.KeyMaterial) {
	t.Helper()
	_, km := ed25519TargetMaterial(t)
	km.Type = plainEd25519LsigKeyType
	km.BaseKeyType = adminTargetTestTypeEd25519
	km.Category = keys.CategoryDSALsig
	km.Bytecode = randomProgram(t)
	return algocrypto.AddressFromProgram(km.Bytecode), km
}

func TestVerifyBoundedAdminRekeyTargetSelfTests(t *testing.T) {
	registerAdminTargetTestProviders()
	bounded := randomAddress(t)
	edAddr, edKey := ed25519TargetMaterial(t)
	falconLsigAddr, falconLsigKey := falconLsigTargetMaterial(t, plainFalcon1024LsigKeyType)
	edLsigAddr, edLsigKey := ed25519LsigTargetMaterial(t)
	composedAddr, composedKey := falconLsigTargetMaterial(t, composedTestKeyType)
	witnessAddr := randomAddress(t)
	tamperedAddr, tamperedKey := ed25519TargetMaterial(t)
	tamperedKey.PublicKey[0] ^= 1
	// A LogicSig credential whose stored program hashes to some other address.
	driftedAddr, driftedKey := falconLsigTargetMaterial(t, plainFalcon1024LsigKeyType)
	driftedKey.Bytecode = randomProgram(t)

	session := adminTargetFakeSession{keys: map[string]*coresigning.KeyMaterial{
		edAddr.String():         edKey,
		falconLsigAddr.String(): falconLsigKey,
		edLsigAddr.String():     edLsigKey,
		composedAddr.String():   composedKey,
		witnessAddr.String():    {Type: "aplane.witness-falcon1024.v1", Category: keys.CategoryWitness},
		tamperedAddr.String():   tamperedKey,
		driftedAddr.String():    driftedKey,
	}}
	txn := func(sender, target types.Address) types.Transaction {
		return types.Transaction{Header: types.Header{Sender: sender, RekeyTo: target}}
	}

	for name, tx := range map[string]types.Transaction{
		"native ed25519":                 txn(bounded, edAddr),
		"falcon LogicSig":                txn(bounded, falconLsigAddr),
		"ed25519 LogicSig":               txn(bounded, edLsigAddr),
		"bounded account back to itself": txn(bounded, bounded),
		"held sender back to itself":     txn(edAddr, edAddr),
	} {
		if err := verifyBoundedAdminRekeyTarget(context.Background(), session, tx, bounded.String()); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	unheld := randomAddress(t)
	for name, tx := range map[string]types.Transaction{
		"not held":                     txn(bounded, unheld),
		"witness":                      txn(bounded, witnessAddr),
		"composed template":            txn(bounded, composedAddr),
		"tampered public key":          txn(bounded, tamperedAddr),
		"program does not derive":      txn(bounded, driftedAddr),
		"unheld sender back to itself": txn(unheld, unheld),
	} {
		err := verifyBoundedAdminRekeyTarget(context.Background(), session, tx, bounded.String())
		if err == nil || err.Kind != ErrorBoundedAdminTargetRejected {
			t.Fatalf("%s: err = %v, want %s", name, err, ErrorBoundedAdminTargetRejected)
		}
	}
	// A native Ed25519 address is the public key itself: a correctly signing
	// key looked up under another address is still refused.
	session.keys[tamperedAddr.String()] = edKey
	if err := verifyBoundedAdminRekeyTarget(context.Background(), session, txn(bounded, tamperedAddr), bounded.String()); err == nil || err.Kind != ErrorBoundedAdminTargetRejected {
		t.Fatalf("address mismatch: err = %v", err)
	}
	// The loaded credential is zeroed after the self-test. The copying
	// session hides that, so observe it through a session that returns the
	// same pointer it holds.
	cp, _ := session.GetKeyWithContext(context.Background(), edAddr.String())
	same := adminTargetFakeSessionSamePointer{km: cp}
	if err := verifyBoundedAdminRekeyTarget(context.Background(), same, txn(bounded, edAddr), bounded.String()); err != nil {
		t.Fatal(err)
	}
	if cp.Value != nil {
		t.Fatal("loaded credential was not zeroed after the self-test")
	}
}

// adminTargetFakeSessionSamePointer returns the stored key material itself,
// so a test can observe zeroing.
type adminTargetFakeSessionSamePointer struct{ km *coresigning.KeyMaterial }

func (f adminTargetFakeSessionSamePointer) GetKeyWithContext(context.Context, string) (*coresigning.KeyMaterial, error) {
	return f.km, nil
}
