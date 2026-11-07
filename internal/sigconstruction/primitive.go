// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sigconstruction

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/aplane-algo/aplane/internal/falconparams"
)

// PrimitiveID identifies exact verification behavior, not just an algorithm family.
type PrimitiveID string

const (
	PrimitiveFalcon1024 PrimitiveID = "falcon1024"
	PrimitiveEd25519    PrimitiveID = "ed25519"
)

// argSlot is one LogicSig argument of a primitive's proof.
type argSlot struct {
	maxSize int
}

// primitiveProfile is everything a construction needs from one primitive. Verify
// opcodes don't share a shape, so each primitive renders its own sequence.
type primitiveProfile struct {
	publicKeySize int
	slots         []argSlot
	// render emits the verification after the message is on the stack, leaving
	// one boolean. Argument slots start at firstArg.
	render func(publicKey []byte, firstArg int) string
	// pack maps a raw signature to the primitive's argument slots.
	pack func(signature []byte) ([][]byte, error)
}

// primitiveProfiles is the closed primitive catalog.
var primitiveProfiles = map[PrimitiveID]*primitiveProfile{
	PrimitiveFalcon1024: {
		publicKeySize: falconparams.PublicKeySize,
		slots:         []argSlot{{maxSize: falconparams.CompressedSignatureMaxSize}},
		render: func(publicKey []byte, firstArg int) string {
			return fmt.Sprintf("arg %d\npushbytes 0x%s\nfalcon_verify\n", firstArg, hex.EncodeToString(publicKey))
		},
		pack: func(signature []byte) ([][]byte, error) {
			if len(signature) == 0 {
				return nil, fmt.Errorf("signature is required for DSA LogicSig")
			}
			if len(signature) > falconparams.CompressedSignatureMaxSize {
				return nil, fmt.Errorf("signature is %d bytes, over the %d-byte Falcon-1024 maximum", len(signature), falconparams.CompressedSignatureMaxSize)
			}
			return [][]byte{signature}, nil
		},
	},
	PrimitiveEd25519: {
		publicKeySize: ed25519.PublicKeySize,
		slots:         []argSlot{{maxSize: ed25519.SignatureSize}},
		render: func(publicKey []byte, firstArg int) string {
			return fmt.Sprintf("arg %d\npushbytes 0x%s\ned25519verify_bare\n", firstArg, hex.EncodeToString(publicKey))
		},
		pack: func(signature []byte) ([][]byte, error) {
			if len(signature) != ed25519.SignatureSize {
				return nil, fmt.Errorf("invalid Ed25519 signature size: expected %d, got %d", ed25519.SignatureSize, len(signature))
			}
			return [][]byte{signature}, nil
		},
	},
}
