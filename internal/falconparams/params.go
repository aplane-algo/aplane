// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package falconparams owns client-safe Falcon-1024 size constants shared by
// LogicSig, witness, and signer metadata. It deliberately does not import the
// CGo Falcon implementation; signer-only consistency tests pin these literals
// to the upstream library.
package falconparams

const (
	PublicKeySize  = 1793
	PrivateKeySize = 2305

	// CompressedSignatureMaxSize is the theoretical maximum emitted by
	// github.com/algorand/falcon's deterministic compressed Falcon-1024 signer.
	// It is distinct from Falcon's 1280-byte padded format and the protocol's
	// larger native-PQ wire allocation bound.
	CompressedSignatureMaxSize = 1423
)
