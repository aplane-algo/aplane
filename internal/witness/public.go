// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package witness

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	PublicReferenceSchema = "aplane.witness-key-public.v1"
	maxPublicReference    = 16 * 1024
)

var ErrUnsupportedPublicReferenceSchema = errors.New("unsupported witness public-reference schema")

// PublicReference is the canonical non-secret witness identity projection.
type PublicReference struct {
	Schema       string `json:"schema"`
	KeyType      string `json:"key_type"`
	WitnessKeyID string `json:"witness_key_id"`
	PublicKeyHex string `json:"public_key_hex"`
}

// NewPublicReference validates and constructs a canonical public reference.
func NewPublicReference(keyType, keyID, publicKeyHex string) (PublicReference, error) {
	if !IsKeyType(keyType) {
		return PublicReference{}, fmt.Errorf("key type %q is not a witness key type", keyType)
	}
	keyID, err := NormalizeID(keyID)
	if err != nil {
		return PublicReference{}, err
	}
	if publicKeyHex == "" || publicKeyHex != strings.ToLower(publicKeyHex) || strings.TrimSpace(publicKeyHex) != publicKeyHex {
		return PublicReference{}, fmt.Errorf("public_key_hex must be canonical lowercase hex")
	}
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return PublicReference{}, fmt.Errorf("public_key_hex must be canonical lowercase hex: %w", err)
	}
	derivedID, err := ID(keyType, publicKey)
	if err != nil {
		return PublicReference{}, err
	}
	if derivedID != keyID {
		return PublicReference{}, fmt.Errorf("witness_key_id does not match key_type and public_key_hex")
	}
	return PublicReference{
		Schema:       PublicReferenceSchema,
		KeyType:      keyType,
		WitnessKeyID: keyID,
		PublicKeyHex: publicKeyHex,
	}, nil
}

// ParsePublicReference strictly decodes and validates a public reference.
func ParsePublicReference(data []byte) (PublicReference, error) {
	if len(data) == 0 || len(data) > maxPublicReference {
		return PublicReference{}, fmt.Errorf("public witness reference size %d is invalid", len(data))
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var reference PublicReference
	if err := decoder.Decode(&reference); err != nil {
		return PublicReference{}, fmt.Errorf("decode public witness reference: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return PublicReference{}, fmt.Errorf("decode public witness reference: %w", err)
	}
	if reference.Schema != PublicReferenceSchema {
		return PublicReference{}, fmt.Errorf("%w %q", ErrUnsupportedPublicReferenceSchema, reference.Schema)
	}
	return NewPublicReference(reference.KeyType, reference.WitnessKeyID, reference.PublicKeyHex)
}

func requireEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}
