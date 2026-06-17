// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package family

import "crypto/ed25519"

const (
	Name              = "ed25519lsig"
	KeyTypeV1         = "aplane.ed25519lsig.v1"
	PublicKeySize     = ed25519.PublicKeySize
	PrivateKeySize    = ed25519.PrivateKeySize
	MaxSignatureSize  = ed25519.SignatureSize
	MnemonicScheme    = "algorand"
	MnemonicWordCount = 25
	DisplayColor      = "36"
	TEALVersion       = 12
)
