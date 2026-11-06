// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package verify checks signature constructions against public inputs. It links
// the upstream Falcon implementation (CGo), so only signer-side code may import
// it; clients pass signatures through opaquely and rely on signer assembly plus
// on-chain LogicSig enforcement. It holds no private material and no signing.
package verify

import (
	"crypto/ed25519"
	"fmt"

	"github.com/algorand/falcon"
	"github.com/algorandfoundation/falcon-signatures/falcongo"
	"github.com/aplane-algo/aplane/internal/falconparams"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
)

// Verify checks every component of a construction against its own key and proof
// slots. The message is whatever the caller's role signs: construction verification
// picks no role and derives no transcript.
//
// A one-component proof is the raw signature, so a witness or receipt passes it as
// one slot. No multi-component signature encoding exists, so a caller holding such
// a proof must pass its slots.
func Verify(construction sigconstruction.Construction, publicKey, message []byte, proof ...[]byte) error {
	keys, err := construction.SplitPublicKey(publicKey)
	if err != nil {
		return err
	}
	layout := construction.Layout()
	if len(proof) != layout.Count() {
		return fmt.Errorf("construction %q takes %d proof slots, got %d", construction.ID(), layout.Count(), len(proof))
	}
	components := layout.Components()
	for i, component := range components {
		slots := proof[component.Start : component.Start+component.Count()]
		if err := verifyPrimitive(component.Primitive, keys[i], message, slots); err != nil {
			if len(components) == 1 {
				return err
			}
			return fmt.Errorf("component %q: %w", component.Name, err)
		}
	}
	return nil
}

func verifyPrimitive(primitive sigconstruction.PrimitiveID, publicKey, message []byte, slots [][]byte) error {
	switch primitive {
	case sigconstruction.PrimitiveFalcon1024:
		return verifyFalcon1024(publicKey, message, slots[0])
	case sigconstruction.PrimitiveEd25519:
		return verifyEd25519(publicKey, message, slots[0])
	default:
		return fmt.Errorf("primitive %q has no verifier", primitive)
	}
}

func verifyFalcon1024(publicKey, message, signature []byte) error {
	if len(signature) == 0 || len(signature) > falconparams.CompressedSignatureMaxSize {
		return fmt.Errorf("falcon1024 signature length %d invalid (expected 1..%d bytes)", len(signature), falconparams.CompressedSignatureMaxSize)
	}
	var pub falcongo.PublicKey
	copy(pub[:], publicKey)
	if err := falcongo.Verify(message, falcon.CompressedSignature(signature), pub); err != nil {
		return fmt.Errorf("falcon1024 signature verification failed: %w", err)
	}
	return nil
}

func verifyEd25519(publicKey, message, signature []byte) error {
	if !ed25519.Verify(ed25519.PublicKey(publicKey), message, signature) {
		return fmt.Errorf("ed25519 signature verification failed")
	}
	return nil
}
