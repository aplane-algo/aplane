// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/signing"
)

// The LogicSigProvider is family-neutral: it resolves a key's family through
// the logicsigdsa registry, hands the private key to the family's signer ops,
// and owns the key material lifecycle. These tests drive it with a pure-Go
// fake family so they cover the provider's own checks without any real
// cryptography. Real families are covered through their registration entry
// points (for example lsig/falcon1024/signerreg).

const (
	fakeFamily       = "fakedsa"
	fakeKeyType      = "test.fakedsa.v1"
	otherFamily      = "otherdsa"
	otherKeyType     = "test.otherdsa.v1"
	fakePrivateKeyLn = 32
)

// fakeDSA is the smallest LogicSigDSA + LSigProvider that the registry
// accepts, so a versioned key type resolves to a routing family.
type fakeDSA struct {
	keyType string
	family  string
}

func (f *fakeDSA) KeyType() string                                { return f.keyType }
func (f *fakeDSA) RoutingFamily() string                          { return f.family }
func (f *fakeDSA) Version() int                                   { return 1 }
func (f *fakeDSA) CryptoSignatureSize() int                       { return sha256.Size }
func (f *fakeDSA) MnemonicScheme() string                         { return "none" }
func (f *fakeDSA) MnemonicWordCount() int                         { return 0 }
func (f *fakeDSA) DisplayColor() string                           { return "0" }
func (f *fakeDSA) Category() string                               { return lsigprovider.CategoryDSALsig }
func (f *fakeDSA) DisplayName() string                            { return f.keyType }
func (f *fakeDSA) Description() string                            { return "test DSA" }
func (f *fakeDSA) CreationParams() []lsigprovider.ParameterDef    { return nil }
func (f *fakeDSA) ValidateCreationParams(map[string]string) error { return nil }
func (f *fakeDSA) RuntimeArgs() []lsigprovider.RuntimeArgDef      { return nil }
func (f *fakeDSA) GenerateKeypair(seed []byte) ([]byte, []byte, error) {
	if len(seed) < fakePrivateKeyLn {
		return nil, nil, fmt.Errorf("seed too short")
	}
	priv := append([]byte(nil), seed[:fakePrivateKeyLn]...)
	pub := sha256.Sum256(priv)
	return pub[:], priv, nil
}
func (f *fakeDSA) DeriveLsig(_ context.Context, publicKey []byte, _ map[string]string) ([]byte, string, error) {
	return append([]byte{0x0d}, publicKey...), "FAKEADDRESS", nil
}
func (f *fakeDSA) BuildArgs(signature []byte, _ map[string][]byte) ([][]byte, error) {
	if signature == nil {
		return nil, fmt.Errorf("signature is required")
	}
	return [][]byte{signature}, nil
}
func (f *fakeDSA) Sign(privateKey, message []byte) ([]byte, error) {
	return fakeSignature(privateKey, message), nil
}

// fakeSignature is what the fake family's signer ops produce, so a test can
// check that SignMessage handed the right key and message to the right ops.
func fakeSignature(privateKey, message []byte) []byte {
	h := sha256.New()
	h.Write(privateKey)
	h.Write(message)
	return h.Sum(nil)
}

// fakeOps is a LogicSigSignerOps that records which key type's slot it was
// registered under, so ops resolution by key type and by family is observable.
type fakeOps struct{ tag string }

func (o *fakeOps) Sign(privateKey, message []byte) ([]byte, error) {
	return append([]byte(o.tag+":"), fakeSignature(privateKey, message)...), nil
}

func init() {
	logicsigdsa.RegisterIfAbsent(&fakeDSA{keyType: fakeKeyType, family: fakeFamily})
	logicsigdsa.RegisterIfAbsent(&fakeDSA{keyType: otherKeyType, family: otherFamily})
}

func newFakeProvider() *signing.LogicSigProvider {
	ops := &fakeOps{tag: "versioned"}
	return signing.NewLogicSigProvider(fakeFamily, map[string]signing.LogicSigSignerOps{
		fakeFamily:  &fakeOps{tag: "family"},
		fakeKeyType: ops,
	})
}

func fakePrivateKey() []byte {
	priv := make([]byte, fakePrivateKeyLn)
	for i := range priv {
		priv[i] = byte(i + 1)
	}
	return priv
}

func TestNewLogicSigProviderRequiresOps(t *testing.T) {
	for name, ops := range map[string]map[string]signing.LogicSigSignerOps{
		"empty": {},
		"nil":   {fakeKeyType: nil},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("NewLogicSigProvider did not panic")
				}
			}()
			signing.NewLogicSigProvider(fakeFamily, ops)
		})
	}
}

func TestLogicSigProviderRoutingFamily(t *testing.T) {
	if got := newFakeProvider().RoutingFamily(); got != fakeFamily {
		t.Fatalf("RoutingFamily() = %q, want %q", got, fakeFamily)
	}
}

func TestLogicSigProviderLoadKeyMaterial(t *testing.T) {
	p := newFakeProvider()
	priv := fakePrivateKey()

	km, err := p.LoadKeyMaterial(signing.ProviderKey{Type: fakeKeyType, PrivateKey: priv})
	if err != nil {
		t.Fatalf("LoadKeyMaterial() error = %v", err)
	}
	if km.Type != fakeKeyType {
		t.Fatalf("LoadKeyMaterial() Type = %q, want %q", km.Type, fakeKeyType)
	}
	loaded, ok := km.Value.(*signing.LsigKeyMaterial)
	if !ok {
		t.Fatalf("LoadKeyMaterial() Value = %T, want *signing.LsigKeyMaterial", km.Value)
	}
	if !bytes.Equal(loaded.PrivateKey, priv) {
		t.Fatal("LoadKeyMaterial() did not copy the private key")
	}
	// The provider hands out its own copy: the caller's buffer and the loaded
	// material have independent lifetimes.
	priv[0] ^= 0xff
	if bytes.Equal(loaded.PrivateKey, priv) {
		t.Fatal("LoadKeyMaterial() aliases the caller's private key buffer")
	}
}

func TestLogicSigProviderLoadKeyMaterialRoutesByBaseKeyType(t *testing.T) {
	// A composed key type is unknown to the registry; its base key type
	// decides the family.
	p := newFakeProvider()
	km, err := p.LoadKeyMaterial(signing.ProviderKey{
		Type:        "test.fakedsa-composed.v1",
		BaseKeyType: fakeKeyType,
		PrivateKey:  fakePrivateKey(),
	})
	if err != nil {
		t.Fatalf("LoadKeyMaterial(composed) error = %v", err)
	}
	if km.Type != "test.fakedsa-composed.v1" {
		t.Fatalf("LoadKeyMaterial(composed) Type = %q, want the stored key type", km.Type)
	}
}

func TestLogicSigProviderLoadKeyMaterialRejectsOtherFamilies(t *testing.T) {
	p := newFakeProvider()
	for name, key := range map[string]signing.ProviderKey{
		"zero":                {},
		"unregistered type":   {Type: "nope", PrivateKey: fakePrivateKey()},
		"other family":        {Type: otherKeyType, PrivateKey: fakePrivateKey()},
		"other base key type": {Type: "test.fakedsa-composed.v1", BaseKeyType: otherKeyType, PrivateKey: fakePrivateKey()},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := p.LoadKeyMaterial(key); err == nil {
				t.Fatal("LoadKeyMaterial() error = nil, want error")
			}
		})
	}
}

func TestLogicSigProviderSignMessage(t *testing.T) {
	p := newFakeProvider()
	priv := fakePrivateKey()
	message := []byte("test message to sign")

	km, err := p.LoadKeyMaterial(signing.ProviderKey{Type: fakeKeyType, PrivateKey: priv})
	if err != nil {
		t.Fatalf("LoadKeyMaterial() error = %v", err)
	}
	sig, err := p.SignMessage(km, message)
	if err != nil {
		t.Fatalf("SignMessage() error = %v", err)
	}
	want := append([]byte("versioned:"), fakeSignature(priv, message)...)
	if !bytes.Equal(sig, want) {
		t.Fatalf("SignMessage() = %x, want the versioned ops' signature over the loaded key", sig)
	}
}

func TestLogicSigProviderSignMessageFallsBackToFamilyOps(t *testing.T) {
	// A key whose type has no ops of its own signs with the family's ops.
	p := signing.NewLogicSigProvider(fakeFamily, map[string]signing.LogicSigSignerOps{
		fakeFamily: &fakeOps{tag: "family"},
	})
	priv := fakePrivateKey()
	message := []byte("m")
	sig, err := p.SignMessage(&signing.KeyMaterial{
		Type:  fakeKeyType,
		Value: &signing.LsigKeyMaterial{PrivateKey: priv},
	}, message)
	if err != nil {
		t.Fatalf("SignMessage() error = %v", err)
	}
	want := append([]byte("family:"), fakeSignature(priv, message)...)
	if !bytes.Equal(sig, want) {
		t.Fatalf("SignMessage() = %x, want the family ops' signature", sig)
	}
}

func TestLogicSigProviderSignMessageRejects(t *testing.T) {
	p := newFakeProvider()
	for name, km := range map[string]*signing.KeyMaterial{
		"nil":                nil,
		"other family":       {Type: otherKeyType, Value: &signing.LsigKeyMaterial{PrivateKey: fakePrivateKey()}},
		"unregistered type":  {Type: "nope", Value: &signing.LsigKeyMaterial{PrivateKey: fakePrivateKey()}},
		"invalid value type": {Type: fakeKeyType, Value: "not key material"},
		"nil value":          {Type: fakeKeyType},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := p.SignMessage(km, []byte("message")); err == nil {
				t.Fatal("SignMessage() error = nil, want error")
			}
		})
	}
}

func TestLogicSigProviderSignMessageWithoutOpsForType(t *testing.T) {
	// Ops registered only under an unrelated name: resolution by type, by
	// base type and by family all miss.
	p := signing.NewLogicSigProvider(fakeFamily, map[string]signing.LogicSigSignerOps{
		"unrelated": &fakeOps{tag: "x"},
	})
	_, err := p.SignMessage(&signing.KeyMaterial{
		Type:  fakeKeyType,
		Value: &signing.LsigKeyMaterial{PrivateKey: fakePrivateKey()},
	}, []byte("m"))
	if err == nil {
		t.Fatal("SignMessage() error = nil, want no-ops error")
	}
}

func TestLogicSigProviderZeroKey(t *testing.T) {
	p := newFakeProvider()
	km, err := p.LoadKeyMaterial(signing.ProviderKey{Type: fakeKeyType, PrivateKey: fakePrivateKey()})
	if err != nil {
		t.Fatalf("LoadKeyMaterial() error = %v", err)
	}
	loaded := km.Value.(*signing.LsigKeyMaterial)
	buf := loaded.PrivateKey

	p.ZeroKey(km)

	if !bytes.Equal(buf, make([]byte, len(buf))) {
		t.Fatal("ZeroKey() left private key bytes in the loaded buffer")
	}
	if loaded.PrivateKey != nil {
		t.Fatal("ZeroKey() should drop the private key slice")
	}
	if km.Type != "" || km.Value != nil {
		t.Fatalf("ZeroKey() left Type=%q Value=%v, want cleared", km.Type, km.Value)
	}
}

func TestLogicSigProviderZeroKeyToleratesNilAndForeignValues(t *testing.T) {
	p := newFakeProvider()
	p.ZeroKey(nil)
	km := &signing.KeyMaterial{Type: fakeKeyType, Value: "not key material"}
	p.ZeroKey(km)
	if km.Type != "" || km.Value != nil {
		t.Fatalf("ZeroKey(foreign value) left Type=%q Value=%v, want cleared", km.Type, km.Value)
	}
}
