// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keymgmt

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
)

const AttestorPublicKeyExportSchema = "aplane.attestor-public-key.v1"

// AttestorPublicKeyExport is the public-only JSON envelope emitted when an
// operator exports the verifier input for an attestor component key.
type AttestorPublicKeyExport struct {
	Schema            string `json:"schema"`
	ComponentKey      string `json:"component_key"`
	KeyType           string `json:"key_type"`
	PublicKeyEncoding string `json:"public_key_encoding"`
	PublicKeyHex      string `json:"public_key_hex"`
	PublicKeySize     int    `json:"public_key_size"`
	PublicKeySHA256   string `json:"public_key_sha256"`
	IsComponentKey    bool   `json:"is_component_key"`
	IsSpendingAccount bool   `json:"is_spending_account"`
}

// BuildAttestorPublicKeyExport validates decrypted key metadata and returns a
// deterministic public-only envelope. The selector is recomputed from the
// public key so a misnamed key file cannot produce a misleading export.
func BuildAttestorPublicKeyExport(componentKey string, info *KeyFileInfo) (*AttestorPublicKeyExport, error) {
	if info == nil {
		return nil, fmt.Errorf("key metadata is required")
	}
	return NewAttestorPublicKeyExport(componentKey, info.Type, info.PublicKeyHex)
}

// NewAttestorPublicKeyExport builds an attestor public-key envelope from raw
// metadata values.
func NewAttestorPublicKeyExport(componentKey, keyType, publicKeyHex string) (*AttestorPublicKeyExport, error) {
	selector, err := keytypes.NormalizeComponentKeySelector(componentKey)
	if err != nil {
		return nil, fmt.Errorf("invalid component key selector: %w", err)
	}
	if !keytypes.IsAttestorComponentKeyType(keyType) {
		return nil, fmt.Errorf("key type %q is not an attestor component key type", keyType)
	}

	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(publicKeyHex))
	if err != nil {
		return nil, fmt.Errorf("public key must be hex: %w", err)
	}
	if len(publicKeyBytes) == 0 {
		return nil, fmt.Errorf("public key is required")
	}
	wantSize, ok := keytypes.ComponentPublicKeySize(keyType)
	if !ok {
		return nil, fmt.Errorf("key type %q is not an attestor component key type", keyType)
	}
	if len(publicKeyBytes) != wantSize {
		return nil, fmt.Errorf("component public key length %d invalid (expected %d bytes)", len(publicKeyBytes), wantSize)
	}

	derivedSelector, err := keytypes.ComponentKeySelector(keyType, publicKeyBytes)
	if err != nil {
		return nil, err
	}
	if derivedSelector != selector {
		return nil, fmt.Errorf("component key selector %q does not match public key-derived selector %q", selector, derivedSelector)
	}

	publicKeySHA256 := sha256.Sum256(publicKeyBytes)
	return &AttestorPublicKeyExport{
		Schema:            AttestorPublicKeyExportSchema,
		ComponentKey:      selector,
		KeyType:           keyType,
		PublicKeyEncoding: "hex",
		PublicKeyHex:      hex.EncodeToString(publicKeyBytes),
		PublicKeySize:     len(publicKeyBytes),
		PublicKeySHA256:   hex.EncodeToString(publicKeySHA256[:]),
		IsComponentKey:    true,
		IsSpendingAccount: false,
	}, nil
}
