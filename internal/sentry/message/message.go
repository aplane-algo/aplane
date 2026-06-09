// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package message constructs the role-separated messages signed by sentry keys.
package message

import (
	"crypto/sha512"
	"fmt"
)

const DomainTagV1 = "APLANE_SENTRY_V1"

type Role byte

const (
	RoleUser   Role = 0x01
	RoleSentry Role = 0x02
)

func (r Role) Valid() bool {
	return r == RoleUser || r == RoleSentry
}

func (r Role) String() string {
	switch r {
	case RoleUser:
		return "user"
	case RoleSentry:
		return "sentry"
	default:
		return fmt.Sprintf("unknown(%d)", byte(r))
	}
}

// ComponentMessage returns SHA512/256("APLANE_SENTRY_V1" || role || txid).
func ComponentMessage(role Role, txid [32]byte) [32]byte {
	input := make([]byte, 0, len(DomainTagV1)+1+len(txid))
	input = append(input, DomainTagV1...)
	input = append(input, byte(role))
	input = append(input, txid[:]...)
	return sha512.Sum512_256(input)
}

// ComponentMessageBytes validates role and txid bytes before constructing the
// component message.
func ComponentMessageBytes(role Role, txid []byte) ([32]byte, error) {
	var digest [32]byte
	if !role.Valid() {
		return digest, fmt.Errorf("invalid component role %d", byte(role))
	}
	if len(txid) != len(digest) {
		return digest, fmt.Errorf("txid length %d invalid (expected %d bytes)", len(txid), len(digest))
	}
	copy(digest[:], txid)
	return ComponentMessage(role, digest), nil
}
