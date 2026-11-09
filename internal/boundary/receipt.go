// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package boundary

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
)

// ReceiptSchemaV1 identifies a resolved account receipt.
const ReceiptSchemaV1 = "aplane.boundary-receipt.v1"

// Receipt documents an account after generation, with every reference resolved.
// It holds no key material, so it does not reconstruct the account, which
// recovers from its encrypted credential or a backup. Its parameters do include
// a rekey-to list's addresses, which the chain never reveals, so a receipt for an
// account with one is private.
type Receipt struct {
	Schema             string            `json:"schema"`
	Address            string            `json:"address"`
	KeyType            string            `json:"key_type"`
	Parameters         map[string]string `json:"parameters"`
	CosignerKeyID      string            `json:"cosigner_key_id,omitempty"`
	GrammarFingerprint string            `json:"grammar_fingerprint"`
	ShapeFingerprint   string            `json:"selected_shape_fingerprint"`
	BoundaryDigest     string            `json:"boundary_digest"`
}

// Encode returns the receipt as indented JSON. A receipt names the saved account,
// so one without an address is an error: a preparation is not a receipt.
func (r Receipt) Encode() ([]byte, error) {
	if r.Address == "" {
		return nil, fmt.Errorf("a receipt needs the generated address")
	}
	r.Schema = ReceiptSchemaV1
	encoded, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode receipt: %w", err)
	}
	return append(encoded, '\n'), nil
}

// RecipientListDigest is a short comparison value for a canonical recipient list,
// so a reviewer can tell two long lists apart without reading them.
func RecipientListDigest(recipients string) string {
	sum := sha512.Sum512_256(boundedmeta.AppendField([]byte("APLANE_BOUNDARY_RECIPIENTS_V1"), []byte(recipients)))
	return hex.EncodeToString(sum[:])
}
