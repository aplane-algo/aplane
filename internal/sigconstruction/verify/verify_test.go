// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
	"github.com/aplane-algo/aplane/internal/falconparams"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
)

type testKey struct {
	primitive sigconstruction.PrimitiveID
	public    []byte
	sign      func(t *testing.T, message []byte) []byte
}

func falconKey(t *testing.T) testKey {
	t.Helper()
	seed := make([]byte, 48)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	pair, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{sigconstruction.PrimitiveFalcon1024, pair.PublicKey[:], func(t *testing.T, message []byte) []byte {
		t.Helper()
		signature, err := pair.Sign(message)
		if err != nil {
			t.Fatal(err)
		}
		return signature
	}}
}

func ed25519Key(t *testing.T) testKey {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{sigconstruction.PrimitiveEd25519, public, func(_ *testing.T, message []byte) []byte {
		return ed25519.Sign(private, message)
	}}
}

// composite builds a local all-of construction with its canonical public key.
func composite(t *testing.T, keys ...testKey) (sigconstruction.Construction, []byte) {
	t.Helper()
	specs := make([]sigconstruction.ComponentSpec, len(keys))
	var public []byte
	for i, key := range keys {
		specs[i] = sigconstruction.ComponentSpec{Name: fmt.Sprintf("part%d", i), Primitive: key.primitive}
		public = append(public, key.public...)
	}
	construction, err := sigconstruction.New(sigconstruction.Definition{ID: "example-allof", Components: specs})
	if err != nil {
		t.Fatal(err)
	}
	return construction, public
}

func proofFor(t *testing.T, message []byte, keys ...testKey) [][]byte {
	t.Helper()
	proof := make([][]byte, len(keys))
	for i, key := range keys {
		proof[i] = key.sign(t, message)
	}
	return proof
}

func TestProductionConstructionsVerifyRawSignatures(t *testing.T) {
	message := []byte("message")
	for name, test := range map[string]struct {
		construction sigconstruction.Construction
		key          testKey
	}{
		"Falcon":  {sigconstruction.Falcon1024(), falconKey(t)},
		"Ed25519": {sigconstruction.Ed25519(), ed25519Key(t)},
	} {
		t.Run(name, func(t *testing.T) {
			signature := test.key.sign(t, message)
			if err := Verify(test.construction, test.key.public, message, signature); err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			tampered := bytes.Clone(signature)
			tampered[len(tampered)/2] ^= 0xff
			if err := Verify(test.construction, test.key.public, message, tampered); err == nil {
				t.Fatal("Verify() accepted a tampered signature")
			}
			if err := Verify(test.construction, test.key.public, []byte("other"), signature); err == nil {
				t.Fatal("Verify() accepted the wrong message")
			}
			if err := Verify(test.construction, test.key.public[1:], message, signature); err == nil {
				t.Fatal("Verify() accepted a short key")
			}
			if err := Verify(test.construction, test.key.public, message); err == nil {
				t.Fatal("Verify() accepted no proof")
			}
			if err := Verify(test.construction, test.key.public, message, signature, signature); err == nil {
				t.Fatal("Verify() accepted an extra proof slot")
			}
		})
	}
}

// Clients see these through "cosigner_signature invalid: %v".
func TestOneComponentErrorsKeepTheirText(t *testing.T) {
	key := falconKey(t)
	message := []byte("message")
	for name, test := range map[string]struct {
		signature []byte
		want      string
	}{
		"empty":     {nil, "falcon1024 signature length 0 invalid (expected 1..1423 bytes)"},
		"oversized": {make([]byte, falconparams.CompressedSignatureMaxSize+1), "falcon1024 signature length 1424 invalid (expected 1..1423 bytes)"},
		"wrong":     {make([]byte, 64), "falcon1024 signature verification failed: "},
	} {
		t.Run(name, func(t *testing.T) {
			err := Verify(sigconstruction.Falcon1024(), key.public, message, test.signature)
			if err == nil || !strings.HasPrefix(err.Error(), test.want) {
				t.Fatalf("Verify() error = %v, want prefix %q", err, test.want)
			}
		})
	}
}

func TestZeroConstructionVerifiesNothing(t *testing.T) {
	if err := Verify(sigconstruction.Construction{}, nil, []byte("message")); err == nil {
		t.Fatal("Verify() accepted a zero construction")
	}
}

// A composite proof is valid only with every component, in order, over the one
// message. The cases cover a transaction proof and a receipt alike, since a receipt
// differs only in the transcript it signs.
func TestCompositeProofRequiresEveryComponent(t *testing.T) {
	falcon, ed, second := falconKey(t), ed25519Key(t), ed25519Key(t)
	txid := bytes.Repeat([]byte{7}, 32)
	receipt := bytes.Repeat([]byte{9}, 32)
	for name, keys := range map[string][]testKey{
		"Falcon then Ed25519": {falcon, ed},
		"Ed25519 then Falcon": {ed, falcon},
		"three components":    {ed, falcon, second},
	} {
		t.Run(name, func(t *testing.T) {
			construction, public := composite(t, keys...)
			for label, message := range map[string][]byte{"transaction": txid, "receipt": receipt} {
				proof := proofFor(t, message, keys...)
				if err := Verify(construction, public, message, proof...); err != nil {
					t.Fatalf("%s: Verify() error = %v", label, err)
				}
				if err := Verify(construction, public, message, proof[:len(proof)-1]...); err == nil {
					t.Fatalf("%s: Verify() accepted a missing component", label)
				}
				for i := range keys {
					mutated := append([][]byte(nil), proof...)
					if keys[i].primitive == sigconstruction.PrimitiveEd25519 {
						mutated[i] = ed25519Key(t).sign(t, message)
					} else {
						mutated[i] = falconKey(t).sign(t, message)
					}
					err := Verify(construction, public, message, mutated...)
					if err == nil || !strings.Contains(err.Error(), fmt.Sprintf(`component "part%d"`, i)) {
						t.Fatalf("%s: wrong component %d: Verify() error = %v", label, i, err)
					}
				}
			}
			// One transcript's proof must not pass for the other.
			if err := Verify(construction, public, receipt, proofFor(t, txid, keys...)...); err == nil {
				t.Fatal("Verify() accepted a transaction proof as a receipt")
			}
			// A mix of transcripts must fail in the component that signed the other.
			mixed := proofFor(t, txid, keys...)
			mixed[len(mixed)-1] = keys[len(keys)-1].sign(t, receipt)
			if err := Verify(construction, public, txid, mixed...); err == nil {
				t.Fatal("Verify() accepted a proof that mixes transcripts")
			}
		})
	}
}

func TestCompositeProofRefusesSwappedSlots(t *testing.T) {
	falcon, ed := falconKey(t), ed25519Key(t)
	construction, public := composite(t, falcon, ed)
	message := []byte("message")
	proof := proofFor(t, message, falcon, ed)
	if err := Verify(construction, public, message, proof[1], proof[0]); err == nil {
		t.Fatal("Verify() accepted swapped proof slots")
	}
}

// A key or proof with bytes after its encoding is a different value, not the same
// one with padding. Every primitive, alone or inside a composite, refuses it.
func TestTrailingBytesAreRefused(t *testing.T) {
	message := []byte("message")
	withByte := func(b []byte) []byte { return append(bytes.Clone(b), 0) }
	for name, test := range map[string]struct {
		construction sigconstruction.Construction
		key          testKey
	}{
		"Falcon":  {sigconstruction.Falcon1024(), falconKey(t)},
		"Ed25519": {sigconstruction.Ed25519(), ed25519Key(t)},
	} {
		t.Run(name, func(t *testing.T) {
			signature := test.key.sign(t, message)
			if err := Verify(test.construction, test.key.public, message, signature); err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if err := Verify(test.construction, test.key.public, message, withByte(signature)); err == nil {
				t.Fatal("Verify() accepted a signature with a trailing byte")
			}
			if err := Verify(test.construction, withByte(test.key.public), message, signature); err == nil {
				t.Fatal("Verify() accepted a public key with a trailing byte")
			}
		})
	}
	t.Run("composite", func(t *testing.T) {
		falcon, ed := falconKey(t), ed25519Key(t)
		construction, public := composite(t, falcon, ed)
		proof := proofFor(t, message, falcon, ed)
		for i := range proof {
			padded := append([][]byte(nil), proof...)
			padded[i] = withByte(proof[i])
			if err := Verify(construction, public, message, padded...); err == nil {
				t.Fatalf("Verify() accepted component %d with a trailing byte", i)
			}
		}
		if err := Verify(construction, withByte(public), message, proof...); err == nil {
			t.Fatal("Verify() accepted a composite key with a trailing byte")
		}
	})
}

// The canonical key is the components' keys in declared order. The same keys in
// another order are a different key, even when the total length matches.
func TestSwappedComponentKeysAreRefused(t *testing.T) {
	message := []byte("message")
	for name, keys := range map[string][2]testKey{
		"different primitives": {falconKey(t), ed25519Key(t)},
		"same primitive":       {ed25519Key(t), ed25519Key(t)},
	} {
		t.Run(name, func(t *testing.T) {
			construction, public := composite(t, keys[0], keys[1])
			proof := proofFor(t, message, keys[0], keys[1])
			if err := Verify(construction, public, message, proof...); err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			swapped := append(bytes.Clone(keys[1].public), keys[0].public...)
			if err := Verify(construction, swapped, message, proof...); err == nil {
				t.Fatal("Verify() accepted the component keys in swapped order")
			}
		})
	}
}
