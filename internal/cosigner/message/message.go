// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package message constructs the role-separated messages signed by cosigner keys.
package message

import "crypto/sha512"

const DomainTagV1 = "APLANE_COSIGNER_V1"

type Role byte

// RoleCosigner is the role byte every cosigned program compiles into the
// cosigner's message. 0x01 named the retired user role and is never reused.
const RoleCosigner Role = 0x02

// ComponentMessage returns SHA512/256("APLANE_COSIGNER_V1" || role || txid).
func ComponentMessage(role Role, txid [32]byte) [32]byte {
	input := make([]byte, 0, len(DomainTagV1)+1+len(txid))
	input = append(input, DomainTagV1...)
	input = append(input, byte(role))
	input = append(input, txid[:]...)
	return sha512.Sum512_256(input)
}
