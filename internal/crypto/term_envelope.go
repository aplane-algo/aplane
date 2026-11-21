// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// The term envelope is the store's at-rest format for anything encrypted
// under a keyring term. It records which term encrypted it and binds both
// the term and the object's logical identity into the AEAD's authenticated
// data, so a file cannot be silently reinterpreted as a different object.
const (
	// TermEnvelopeVersion distinguishes this format from envelope_version 1
	// (the pre-keyring master-key envelope) and 2 (standalone export).
	TermEnvelopeVersion = 3

	aadDomain = "aplane.term-envelope.v1"
)

// ObjectClass names the kind of object an envelope holds. It is part of the
// authenticated data, so a template can never be opened as a credential.
type ObjectClass string

const (
	// ClassAccountKey is a managed account credential, selected by address.
	ClassAccountKey ObjectClass = "account-key"
	// ClassCosignerCredential is a cosigner witness credential, selected by
	// Witness Key ID.
	ClassCosignerCredential ObjectClass = "cosigner-credential"
	// ClassKeyTypeTemplate is an installed key-type template, selected by
	// key type.
	ClassKeyTypeTemplate ObjectClass = "keytype-template"
	// ClassSourceTokens is a cosigner policy selector's external-source
	// tokens, selected by policy selector: a Witness Key ID or "default".
	ClassSourceTokens ObjectClass = "source-tokens"
)

// ObjectContext is an object's logical identity: stable across every move
// the store performs. Generation IDs, staging directories, and deleted/
// never appear in it, because ciphertext crosses all of those without
// re-encryption.
type ObjectContext struct {
	Class    ObjectClass
	Selector string
}

// AccountKeyContext identifies a managed account credential.
func AccountKeyContext(address string) ObjectContext {
	return ObjectContext{Class: ClassAccountKey, Selector: address}
}

// CosignerCredentialContext identifies a cosigner witness credential.
func CosignerCredentialContext(witnessKeyID string) ObjectContext {
	return ObjectContext{Class: ClassCosignerCredential, Selector: witnessKeyID}
}

// KeyTypeTemplateContext identifies an installed key-type template.
func KeyTypeTemplateContext(keyType string) ObjectContext {
	return ObjectContext{Class: ClassKeyTypeTemplate, Selector: keyType}
}

// SourceTokensContext identifies the source token file of one cosigner
// policy selector: a Witness Key ID, or "default" for the node default.
func SourceTokensContext(selector string) ObjectContext {
	return ObjectContext{Class: ClassSourceTokens, Selector: selector}
}

func (c ObjectContext) validate() error {
	switch c.Class {
	case ClassAccountKey, ClassCosignerCredential, ClassKeyTypeTemplate, ClassSourceTokens:
	case "":
		return fmt.Errorf("object context requires a class")
	default:
		return fmt.Errorf("unknown object class %q", c.Class)
	}
	if c.Selector == "" {
		return fmt.Errorf("object context for class %q requires a selector", c.Class)
	}
	if strings.ContainsRune(c.Selector, 0) {
		return fmt.Errorf("object selector must not contain NUL")
	}
	return nil
}

// String renders the context for error messages.
func (c ObjectContext) String() string {
	return string(c.Class) + ":" + c.Selector
}

// encryptedDataTerm is the on-disk envelope. The term is recorded in the
// clear so a reader knows which key to select, and bound into the AAD so it
// cannot be edited.
type encryptedDataTerm struct {
	EnvelopeVersion int    `json:"envelope_version"`
	Term            int64  `json:"term"`
	Nonce           string `json:"nonce"`
	Ciphertext      string `json:"ciphertext"`
}

// InspectTermEnvelope reports whether data declares an encryption-envelope
// version and, when it does, requires the current term-envelope format and a
// positive term. Plaintext generation members do not declare the field and
// return present=false. The term is 0 whenever present is false or err is
// set. It never decrypts: callers that use the term as authority must also
// open the same byte buffer with its expected logical ObjectContext.
func InspectTermEnvelope(data []byte) (term int64, present bool, err error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		// Generation structural inventory is content-agnostic. Higher-level
		// validators reject malformed plaintext; a non-JSON member cannot be
		// mistaken for an envelope because it declares no parsed version.
		return 0, false, nil
	}
	if _, present := object["envelope_version"]; !present {
		return 0, false, nil
	}
	encrypted, err := parseTermEnvelope(data)
	if err != nil {
		return 0, true, err
	}
	return encrypted.Term, true, nil
}

// The sizes cipher.NewGCM uses, which every term envelope has.
const (
	termEnvelopeNonceBytes = 12
	termEnvelopeTagBytes   = 16
)

// TermEnvelopeLen is the length of the envelope Keyring.Seal writes for
// plaintextLen bytes of plaintext under term. Nothing else changes it, so a
// caller can bound an object's encrypted size before it holds the keyring
// that will seal it.
func TermEnvelopeLen(plaintextLen int, term int64) int {
	data, _ := json.MarshalIndent(encryptedDataTerm{
		EnvelopeVersion: TermEnvelopeVersion,
		Term:            term,
		Nonce:           strings.Repeat("A", base64.StdEncoding.EncodedLen(termEnvelopeNonceBytes)),
		Ciphertext:      strings.Repeat("A", base64.StdEncoding.EncodedLen(plaintextLen+termEnvelopeTagBytes)),
	}, "", "  ")
	return len(data)
}

func sealUnderTerm(plaintext, key []byte, term int64, ctx ObjectContext) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext, err := sealWithRandomNonce(gcm, plaintext, aadFor(term, ctx))
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(encryptedDataTerm{
		EnvelopeVersion: TermEnvelopeVersion,
		Term:            term,
		Nonce:           base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:      base64.StdEncoding.EncodeToString(ciphertext),
	}, "", "  ")
}

// openUnderTerm opens an envelope parseTermEnvelope returned, under the
// term it names.
func openUnderTerm(encrypted encryptedDataTerm, key []byte, ctx ObjectContext) ([]byte, error) {
	nonce, err := base64.StdEncoding.DecodeString(encrypted.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if err := validateGCMNonce(nonce, gcm); err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aadFor(encrypted.Term, ctx))
	if err != nil {
		// A wrong key, an edited term, and a mismatched object identity are
		// deliberately indistinguishable here: all three mean this envelope
		// is not what the caller asked for.
		return nil, fmt.Errorf("failed to decrypt %s: %w", ctx, err)
	}
	return plaintext, nil
}

// parseTermEnvelope strictly parses one canonical term envelope without
// decrypting it. The version is probed first, so another envelope version is
// refused as such rather than for the fields this format does not have.
func parseTermEnvelope(encoded []byte) (encryptedDataTerm, error) {
	var probe struct {
		EnvelopeVersion int `json:"envelope_version"`
	}
	if err := json.Unmarshal(encoded, &probe); err != nil {
		return encryptedDataTerm{}, fmt.Errorf("failed to parse encrypted data: %w", err)
	}
	if probe.EnvelopeVersion != TermEnvelopeVersion {
		return encryptedDataTerm{}, fmt.Errorf(
			"envelope_version %d is not a term envelope (expected %d)",
			probe.EnvelopeVersion, TermEnvelopeVersion,
		)
	}
	var encrypted encryptedDataTerm
	if err := decodeJSONStrict(encoded, &encrypted); err != nil {
		return encryptedDataTerm{}, fmt.Errorf("failed to parse encrypted data: %w", err)
	}
	if encrypted.Term <= 0 {
		return encryptedDataTerm{}, fmt.Errorf("failed to parse encrypted data: term envelope has no term")
	}
	canonical, err := json.MarshalIndent(encrypted, "", "  ")
	if err != nil {
		return encryptedDataTerm{}, fmt.Errorf("canonicalize term envelope: %w", err)
	}
	if !bytes.Equal(encoded, canonical) {
		return encryptedDataTerm{}, fmt.Errorf("failed to parse encrypted data: term envelope is not canonical JSON")
	}
	return encrypted, nil
}
