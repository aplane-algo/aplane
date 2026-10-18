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

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	falconsignerops "github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
)

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
		{"plain falcon lsig", keys.CategoryDSALsig, "aplane.falcon1024.v1", false, ""},
		{"plain ed25519 lsig", keys.CategoryDSALsig, "aplane.ed25519.v1", false, ""},
		{"bounded lsig", keys.CategoryDSALsig, "aplane.falcon1024-allowlist-alock.v1", true, "bounded"},
		{"guarded lsig", keys.CategoryDSALsig, "aplane.falcon1024-cosigner1024.v1", false, "guarded"},
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
	sender := randomAddress(t)
	held := randomAddress(t)
	boundedHeld := randomAddress(t)
	foreign := randomAddress(t)
	svc := &Service{Planner: &Planner{Snapshot: func() PlannerRuntimeSnapshot {
		return PlannerRuntimeSnapshot{
			KeyTypes: map[string]string{
				held.String():        "ed25519",
				boundedHeld.String(): "aplane.falcon1024-allowlist-alock.v1",
			},
			KeyMetadata: map[string]PlannerKeyMetadata{
				held.String():        {Category: keys.CategoryEd25519},
				boundedHeld.String(): {Category: keys.CategoryDSALsig, BoundedAuthorization: &boundedmeta.Metadata{}},
			},
		}
	}}}
	txn := func(target types.Address) types.Transaction {
		return types.Transaction{Header: types.Header{Sender: sender, RekeyTo: target}}
	}
	if err := svc.checkBoundedAdminRekeyTarget(txn(held)); err != nil {
		t.Fatalf("held ed25519 target refused: %v", err)
	}
	if err := svc.checkBoundedAdminRekeyTarget(txn(sender)); err != nil {
		t.Fatalf("self-rekey refused: %v", err)
	}
	for name, target := range map[string]types.Address{"foreign": foreign, "bounded": boundedHeld} {
		err := svc.checkBoundedAdminRekeyTarget(txn(target))
		if err == nil || err.Kind != ErrorBoundedAdminTargetRejected {
			t.Fatalf("%s target: err = %v, want %s", name, err, ErrorBoundedAdminTargetRejected)
		}
	}
	// The check runs before policy and consults no policy flag. A planner
	// without a snapshot is a configuration error, not a refusal.
	if err := (&Service{Planner: &Planner{}}).checkBoundedAdminRekeyTarget(txn(held)); err == nil || err.Kind != ErrorInternal {
		t.Fatalf("missing snapshot: err = %v", err)
	}
}

// Test-only signing providers under test-only key types, so the package's
// shared provider registry never gains a real family that other tests in
// this package expect to be absent. They sign with the real primitives.
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
	if privateKey, ok := km.Value.([]byte); ok {
		cp.Value = append([]byte(nil), privateKey...)
	}
	return &cp, nil
}

func ed25519TargetMaterial(t *testing.T, category string) (types.Address, *coresigning.KeyMaterial) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var addr types.Address
	copy(addr[:], pub)
	return addr, &coresigning.KeyMaterial{
		Type:      adminTargetTestTypeEd25519,
		Category:  category,
		Value:     []byte(priv),
		PublicKey: append([]byte(nil), pub...),
	}
}

func falconLsigTargetMaterial(t *testing.T) *coresigning.KeyMaterial {
	t.Helper()
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := falconsignerops.New(nil).GenerateKeypair(seed)
	if err != nil {
		t.Fatal(err)
	}
	return &coresigning.KeyMaterial{
		Type:      adminTargetTestTypeFalcon,
		Category:  keys.CategoryDSALsig,
		Value:     priv,
		PublicKey: pub,
	}
}

func TestVerifyBoundedAdminRekeyTargetSelfTests(t *testing.T) {
	registerAdminTargetTestProviders()
	sender := randomAddress(t)
	edAddr, edKey := ed25519TargetMaterial(t, keys.CategoryEd25519)
	// LogicSig targets are bound by the session lookup, not by the public
	// key, so their addresses are arbitrary here.
	falconLsigAddr := randomAddress(t)
	falconLsigKey := falconLsigTargetMaterial(t)
	edLsigAddr := randomAddress(t)
	_, edLsigKey := ed25519TargetMaterial(t, keys.CategoryDSALsig)
	witnessAddr := randomAddress(t)
	tamperedAddr, tamperedKey := ed25519TargetMaterial(t, keys.CategoryEd25519)
	tamperedKey.PublicKey[0] ^= 1

	session := adminTargetFakeSession{keys: map[string]*coresigning.KeyMaterial{
		edAddr.String():         edKey,
		falconLsigAddr.String(): falconLsigKey,
		edLsigAddr.String():     edLsigKey,
		witnessAddr.String():    {Type: "aplane.witness-falcon1024.v1", Category: keys.CategoryWitness},
		tamperedAddr.String():   tamperedKey,
	}}
	txn := func(target types.Address) types.Transaction {
		return types.Transaction{Header: types.Header{Sender: sender, RekeyTo: target}}
	}

	for name, target := range map[string]types.Address{
		"native ed25519":   edAddr,
		"falcon LogicSig":  falconLsigAddr,
		"ed25519 LogicSig": edLsigAddr,
		"self-rekey":       sender,
	} {
		if err := verifyBoundedAdminRekeyTarget(context.Background(), session, txn(target)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, target := range map[string]types.Address{
		"not held":            randomAddress(t),
		"witness":             witnessAddr,
		"tampered public key": tamperedAddr,
	} {
		err := verifyBoundedAdminRekeyTarget(context.Background(), session, txn(target))
		if err == nil || err.Kind != ErrorBoundedAdminTargetRejected {
			t.Fatalf("%s: err = %v, want %s", name, err, ErrorBoundedAdminTargetRejected)
		}
	}
	// A native Ed25519 address is the public key itself: a correctly signing
	// key looked up under another address is still refused.
	session.keys[tamperedAddr.String()] = edKey
	if err := verifyBoundedAdminRekeyTarget(context.Background(), session, txn(tamperedAddr)); err == nil || err.Kind != ErrorBoundedAdminTargetRejected {
		t.Fatalf("address mismatch: err = %v", err)
	}
	// The loaded credential is zeroed after the self-test: the copy handed
	// out by the session ends with no private material.
	cp, _ := session.GetKeyWithContext(context.Background(), edAddr.String())
	holder := adminTargetFakeSession{keys: map[string]*coresigning.KeyMaterial{edAddr.String(): cp}}
	if err := verifyBoundedAdminRekeyTarget(context.Background(), holder, txn(edAddr)); err != nil {
		t.Fatal(err)
	}
	if cp.Value != nil {
		// The session handed verify a copy of cp, so cp itself is untouched;
		// assert on the copy's behaviour through a session that returns the
		// same pointer instead.
		same := adminTargetFakeSessionSamePointer{km: cp}
		if err := verifyBoundedAdminRekeyTarget(context.Background(), same, txn(edAddr)); err != nil {
			t.Fatal(err)
		}
		if cp.Value != nil {
			t.Fatal("loaded credential was not zeroed after the self-test")
		}
	}
}

// adminTargetFakeSessionSamePointer returns the stored key material itself,
// so a test can observe zeroing.
type adminTargetFakeSessionSamePointer struct{ km *coresigning.KeyMaterial }

func (f adminTargetFakeSessionSamePointer) GetKeyWithContext(context.Context, string) (*coresigning.KeyMaterial, error) {
	return f.km, nil
}
