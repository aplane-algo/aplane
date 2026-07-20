// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package message owns the frozen bounded1 contract-admin transcript.
package message

import (
	"crypto/sha512"
	"fmt"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
)

const (
	DomainV1       = "APLANE_BOUNDED_ADMIN_AUTH_V1"
	OperationRekey = "rekey"
)

// AdminMessage returns the digest signed by a contract admin key.
func AdminMessage(operation string, programBinding, transactionID []byte) ([sha512.Size256]byte, error) {
	if operation != OperationRekey {
		return [sha512.Size256]byte{}, fmt.Errorf("bounded1 does not support admin operation %q", operation)
	}
	if len(programBinding) != sha512.Size256 {
		return [sha512.Size256]byte{}, fmt.Errorf("program binding length %d invalid (expected %d bytes)", len(programBinding), sha512.Size256)
	}
	if len(transactionID) != sha512.Size256 {
		return [sha512.Size256]byte{}, fmt.Errorf("transaction ID length %d invalid (expected %d bytes)", len(transactionID), sha512.Size256)
	}
	var encoded []byte
	encoded = boundedmeta.AppendField(encoded, []byte(DomainV1))
	encoded = boundedmeta.AppendField(encoded, []byte(operation))
	encoded = boundedmeta.AppendField(encoded, programBinding)
	encoded = boundedmeta.AppendField(encoded, transactionID)
	return sha512.Sum512_256(encoded), nil
}

// Prefix returns the exact bytes prepended to TxID by the bounded1 TEAL path.
func Prefix(operation string, programBinding []byte) ([]byte, error) {
	if operation != OperationRekey {
		return nil, fmt.Errorf("bounded1 does not support admin operation %q", operation)
	}
	if len(programBinding) != sha512.Size256 {
		return nil, fmt.Errorf("program binding length %d invalid (expected %d bytes)", len(programBinding), sha512.Size256)
	}
	var encoded []byte
	encoded = boundedmeta.AppendField(encoded, []byte(DomainV1))
	encoded = boundedmeta.AppendField(encoded, []byte(operation))
	encoded = boundedmeta.AppendField(encoded, programBinding)
	encoded = append(encoded, 0, 0, 0, sha512.Size256)
	return encoded, nil
}
