// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"crypto/rand"
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
	// ClassSentryCredential is a sentry witness credential, selected by
	// Witness Key ID.
	ClassSentryCredential ObjectClass = "sentry-credential"
	// ClassKeyTypeTemplate is an installed key-type template, selected by
	// key type.
	ClassKeyTypeTemplate ObjectClass = "keytype-template"
	// ClassRecoveredBatch is a recovered batch's metadata, selected by
	// restore ID.
	ClassRecoveredBatch ObjectClass = "recovered-batch"
	// ClassRecoveredEntry is one recovered entry, selected by restore ID and
	// entry selector.
	ClassRecoveredEntry ObjectClass = "recovered-entry"
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

// SentryCredentialContext identifies a sentry witness credential.
func SentryCredentialContext(witnessKeyID string) ObjectContext {
	return ObjectContext{Class: ClassSentryCredential, Selector: witnessKeyID}
}

// KeyTypeTemplateContext identifies an installed key-type template.
func KeyTypeTemplateContext(keyType string) ObjectContext {
	return ObjectContext{Class: ClassKeyTypeTemplate, Selector: keyType}
}

// RecoveredBatchContext identifies one recovered batch's metadata.
func RecoveredBatchContext(restoreID string) ObjectContext {
	return ObjectContext{Class: ClassRecoveredBatch, Selector: restoreID}
}

// RecoveredEntryContext identifies one entry within a recovered batch.
//
// The two parts share one selector field, which is unambiguous because a
// restore ID is a fixed-shape 128-bit lowercase hex string and so contains no
// separator: the first "/" is always the boundary. If restore IDs ever gain a
// free-form shape, this must become two length-prefixed AAD fields rather
// than a join.
func RecoveredEntryContext(restoreID, selector string) ObjectContext {
	return ObjectContext{Class: ClassRecoveredEntry, Selector: restoreID + "/" + selector}
}

func (c ObjectContext) validate() error {
	switch c.Class {
	case ClassAccountKey, ClassSentryCredential, ClassKeyTypeTemplate,
		ClassRecoveredBatch, ClassRecoveredEntry:
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
	Term            int    `json:"term"`
	Nonce           string `json:"nonce"`
	Ciphertext      string `json:"ciphertext"`
}

// envelopeTerm reads the term a term-envelope names, without decrypting.
func envelopeTerm(encryptedJSON []byte) (int, error) {
	var probe struct {
		EnvelopeVersion int `json:"envelope_version"`
		Term            int `json:"term"`
	}
	if err := json.Unmarshal(encryptedJSON, &probe); err != nil {
		return 0, fmt.Errorf("failed to parse encrypted data: %w", err)
	}
	if probe.EnvelopeVersion != TermEnvelopeVersion {
		return 0, fmt.Errorf(
			"envelope_version %d is not a term envelope (expected %d)",
			probe.EnvelopeVersion, TermEnvelopeVersion,
		)
	}
	if probe.Term <= 0 {
		return 0, fmt.Errorf("term envelope has no term")
	}
	return probe.Term, nil
}

func sealUnderTerm(plaintext, key []byte, term int, ctx ObjectContext) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, aadFor(term, ctx))
	return json.MarshalIndent(encryptedDataTerm{
		EnvelopeVersion: TermEnvelopeVersion,
		Term:            term,
		Nonce:           base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:      base64.StdEncoding.EncodeToString(ciphertext),
	}, "", "  ")
}

func openUnderTerm(encryptedJSON, key []byte, term int, ctx ObjectContext) ([]byte, error) {
	var encrypted encryptedDataTerm
	if err := json.Unmarshal(encryptedJSON, &encrypted); err != nil {
		return nil, fmt.Errorf("failed to parse encrypted data: %w", err)
	}
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
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aadFor(term, ctx))
	if err != nil {
		// A wrong key, an edited term, and a mismatched object identity are
		// deliberately indistinguishable here: all three mean this envelope
		// is not what the caller asked for.
		return nil, fmt.Errorf("failed to decrypt %s: %w", ctx, err)
	}
	return plaintext, nil
}
