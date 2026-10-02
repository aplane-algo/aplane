// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package integritysidecar implements the HMAC sidecar that authenticates a
// product store file (a policy document, the node role) against the product store
// keyring. The HMAC covers the file's exact bytes. Only the Header fields are
// security inputs; any digest or timestamp a file's sidecar adds beside them
// is diagnostic.
package integritysidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
)

const (
	Version   = 2
	Algorithm = "hmac-sha256"
)

// Header holds the sidecar fields that carry security meaning. A file's
// sidecar struct embeds it first, ahead of its diagnostic fields.
type Header struct {
	Version       int    `json:"version"`
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	IntegrityTerm int64  `json:"integrity_term"`
	HMAC          string `json:"hmac"`
}

// Errors are the caller's sentinels. Every failure wraps Check plus the
// sentinel for its kind, so callers keep their own errors.Is contract.
type Errors struct {
	Check       error // wrapped by every failure
	Bad         error // malformed, unreadable, or unsignable sidecar
	Missing     error // sidecar file does not exist
	Unsupported error // version, algorithm, or key ID this build does not accept
	Mismatch    error // HMAC does not authenticate the file bytes
}

// Spec binds a sidecar to one keyring integrity domain.
type Spec struct {
	Domain apcrypto.IntegrityDomain
	KeyID  string
	Name   string // the protected file's name in messages, e.g. "policy"
	Errors Errors
}

// Sign returns the security header authenticating data under the keyring's
// current term.
func (s Spec) Sign(data []byte, kr *apcrypto.Keyring) (Header, error) {
	if kr == nil {
		return Header{}, s.fail(s.Errors.Bad, nil, "keyring is required")
	}
	term, mac, err := kr.SignIntegrity(s.Domain, data)
	if err != nil {
		return Header{}, s.fail(s.Errors.Bad, err, "failed to sign %s integrity", s.Name)
	}
	return Header{Version: Version, Algorithm: Algorithm, KeyID: s.KeyID, IntegrityTerm: term, HMAC: mac}, nil
}

// Verify checks the header's security fields and that its HMAC authenticates
// data.
func (s Spec) Verify(data []byte, h *Header, kr *apcrypto.Keyring) error {
	if kr == nil {
		return s.fail(s.Errors.Bad, nil, "keyring is required")
	}
	if h == nil {
		return s.fail(s.Errors.Bad, nil, "missing sidecar data")
	}
	if h.Version != Version {
		return s.fail(s.Errors.Unsupported, nil, "version %d", h.Version)
	}
	if h.Algorithm != Algorithm {
		return s.fail(s.Errors.Unsupported, nil, "algorithm %q", h.Algorithm)
	}
	if h.KeyID != s.KeyID {
		return s.fail(s.Errors.Unsupported, nil, "key_id %q", h.KeyID)
	}
	if h.IntegrityTerm <= 0 {
		return s.fail(s.Errors.Bad, nil, "missing integrity_term")
	}
	if err := validateCanonicalHMAC(h.HMAC); err != nil {
		return s.fail(s.Errors.Bad, err, "invalid hmac encoding")
	}
	if err := kr.VerifyIntegrity(s.Domain, data, h.IntegrityTerm, h.HMAC); err != nil {
		return s.fail(s.Errors.Mismatch, err, "HMAC verification failed")
	}
	return nil
}

// Marshal encodes sidecar, a pointer to a file's sidecar struct, as indented
// JSON with a trailing newline.
func (s Spec) Marshal(sidecar any) ([]byte, error) {
	data, err := json.MarshalIndent(sidecar, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal %s integrity sidecar: %w", s.Name, err)
	}
	return append(data, '\n'), nil
}

// Parse strictly decodes data into sidecar, a pointer to a file's sidecar
// struct: unknown fields and trailing data are rejected. Security fields are
// checked by Verify.
func (s Spec) Parse(data []byte, sidecar any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(sidecar); err != nil {
		return s.fail(s.Errors.Bad, err, "failed to parse sidecar")
	}
	if err := requireJSONEOF(decoder); err != nil {
		return s.fail(s.Errors.Bad, err, "failed to parse sidecar")
	}
	return nil
}

// Load reads and parses the sidecar at path into sidecar.
func (s Spec) Load(path string, sidecar any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s.fail(s.Errors.Missing, err, "sidecar %s", path)
		}
		return s.fail(s.Errors.Bad, err, "failed to read sidecar %s", path)
	}
	return s.Parse(data, sidecar)
}

func (s Spec) fail(kind, cause error, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	if cause == nil {
		return fmt.Errorf("%w: %w: %s", s.Errors.Check, kind, msg)
	}
	return fmt.Errorf("%w: %w: %s: %w", s.Errors.Check, kind, msg, cause)
}

func validateCanonicalHMAC(encoded string) error {
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return err
	}
	if len(decoded) != sha256.Size || encoded != hex.EncodeToString(decoded) {
		return fmt.Errorf("expected canonical lowercase SHA-256 hex")
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	switch err := decoder.Decode(&trailing); err {
	case io.EOF:
		return nil
	case nil:
		return fmt.Errorf("trailing data after JSON document")
	default:
		return fmt.Errorf("trailing data after JSON document: %w", err)
	}
}
