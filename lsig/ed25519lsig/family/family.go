// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package family

import "crypto/ed25519"

const (
	// Name is the qualified registry family ("publisher.family"). It is
	// deliberately "aplane.ed25519" (not "ed25519") so this LogicSig base does
	// not collide with the native "ed25519" key type in the family-keyed
	// registries.
	Name = "aplane.ed25519"
	// KeyTypeV1 is the public key type for the Ed25519 LogicSig base.
	KeyTypeV1         = "aplane.ed25519.v1"
	PublicKeySize     = ed25519.PublicKeySize
	PrivateKeySize    = ed25519.PrivateKeySize
	MaxSignatureSize  = ed25519.SignatureSize
	MnemonicScheme    = "algorand"
	MnemonicWordCount = 25
	DisplayColor      = "36"
	TEALVersion       = 12
)
