// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package noderole

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const (
	IntegritySidecarVersion = 2
	IntegrityAlgorithm      = "hmac-sha256"
	IntegrityKeyID          = "keystore-master-hkdf-node-role-v1"
)

type IntegritySidecar struct {
	Version       int    `json:"version"`
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	IntegrityTerm int64  `json:"integrity_term"`
	HMAC          string `json:"hmac"`
	NodeSHA256    string `json:"node_sha256,omitempty"`
	SignedAtUnix  int64  `json:"signed_at_unix,omitempty"`
	NodeMTimeNS   int64  `json:"node_mtime_ns,omitempty"`
}

func Load(paths storepaths.Paths) (Document, []byte, error) {
	data, err := os.ReadFile(paths.NodeRolePath())
	if err != nil {
		if os.IsNotExist(err) {
			return Document{}, nil, roleError(ErrRoleFileMissing, "node role %s", paths.NodeRolePath())
		}
		return Document{}, nil, roleWrap(ErrRoleFileUnread, err, "failed to read node role %s", paths.NodeRolePath())
	}
	doc, err := ParseDocument(data)
	if err != nil {
		return Document{}, nil, err
	}
	return doc, data, nil
}

func SaveInitial(paths storepaths.Paths, role Role, createdAt time.Time) ([]byte, Document, error) {
	path := paths.NodeRolePath()
	if _, err := os.Stat(path); err == nil {
		return nil, Document{}, roleError(ErrRoleFileExists, "node role %s already exists", path)
	} else if err != nil && !os.IsNotExist(err) {
		return nil, Document{}, roleWrap(ErrRoleFileUnread, err, "failed to stat node role %s", path)
	}
	doc, err := NewDocument(role, createdAt)
	if err != nil {
		return nil, Document{}, err
	}
	data, err := MarshalDocument(doc)
	if err != nil {
		return nil, Document{}, err
	}
	if err := fsutil.WriteFile(path, data); err != nil {
		return nil, Document{}, fmt.Errorf("failed to write node role %s: %w", path, err)
	}
	return data, doc, nil
}

func SaveIdentitySidecarWithKeyring(paths storepaths.Paths, identityID string, roleBytes []byte, kr *apcrypto.Keyring, signedAt time.Time) error {
	return SaveIdentitySidecar(paths, identityID, roleBytes, kr, signedAt)
}

func SaveIdentitySidecar(paths storepaths.Paths, identityID string, roleBytes []byte, kr *apcrypto.Keyring, signedAt time.Time) error {
	if _, err := ParseDocument(roleBytes); err != nil {
		return err
	}
	info, err := os.Stat(paths.NodeRolePath())
	if err != nil {
		return fmt.Errorf("failed to stat node role %s: %w", paths.NodeRolePath(), err)
	}
	sidecar, err := Sign(roleBytes, kr, signedAt, info.ModTime().UnixNano())
	if err != nil {
		return err
	}
	sidecarBytes, err := MarshalSidecar(sidecar)
	if err != nil {
		return err
	}
	path := paths.NodeRoleIntegritySidecar(identityID)
	if err := fsutil.MkdirAll(filepath.Dir(path)); err != nil {
		return fmt.Errorf("failed to create node role sidecar directory: %w", err)
	}
	if err := fsutil.WriteFile(path, sidecarBytes); err != nil {
		return fmt.Errorf("failed to write node role integrity sidecar %s: %w", path, err)
	}
	return nil
}

func LoadAndVerifyWithKeyring(paths storepaths.Paths, identityID string, kr *apcrypto.Keyring) (Document, error) {
	return LoadAndVerify(paths, identityID, kr)
}

func LoadAndVerify(paths storepaths.Paths, identityID string, kr *apcrypto.Keyring) (Document, error) {
	doc, roleBytes, err := Load(paths)
	if err != nil {
		return Document{}, err
	}
	sidecar, err := LoadSidecar(paths.NodeRoleIntegritySidecar(identityID))
	if err != nil {
		return Document{}, err
	}
	if err := Verify(roleBytes, sidecar, kr); err != nil {
		return Document{}, err
	}
	return doc, nil
}

func Sign(roleBytes []byte, kr *apcrypto.Keyring, signedAt time.Time, nodeMTimeNS int64) (*IntegritySidecar, error) {
	if kr == nil {
		return nil, roleError(ErrRoleSidecarBad, "keyring is required")
	}
	if signedAt.IsZero() {
		signedAt = time.Now()
	}
	term, mac, err := kr.SignIntegrity(apcrypto.IntegrityDomainNodeRole, roleBytes)
	if err != nil {
		return nil, roleWrap(ErrRoleSidecarBad, err, "failed to sign node role integrity")
	}
	sum := sha256.Sum256(roleBytes)
	return &IntegritySidecar{
		Version:       IntegritySidecarVersion,
		Algorithm:     IntegrityAlgorithm,
		KeyID:         IntegrityKeyID,
		IntegrityTerm: term,
		HMAC:          mac,
		NodeSHA256:    hex.EncodeToString(sum[:]),
		SignedAtUnix:  signedAt.UTC().Unix(),
		NodeMTimeNS:   nodeMTimeNS,
	}, nil
}

func Verify(roleBytes []byte, sidecar *IntegritySidecar, kr *apcrypto.Keyring) error {
	if kr == nil {
		return roleError(ErrRoleSidecarBad, "keyring is required")
	}
	if sidecar == nil {
		return roleError(ErrRoleSidecarBad, "missing sidecar data")
	}
	if sidecar.Version != IntegritySidecarVersion {
		return roleError(ErrRoleUnsupported, "version %d", sidecar.Version)
	}
	if sidecar.Algorithm != IntegrityAlgorithm {
		return roleError(ErrRoleUnsupported, "algorithm %q", sidecar.Algorithm)
	}
	if sidecar.KeyID != IntegrityKeyID {
		return roleError(ErrRoleUnsupported, "key_id %q", sidecar.KeyID)
	}
	if sidecar.IntegrityTerm <= 0 {
		return roleError(ErrRoleSidecarBad, "missing integrity_term")
	}
	if err := validateCanonicalHMAC(sidecar.HMAC); err != nil {
		return roleWrap(ErrRoleSidecarBad, err, "invalid hmac encoding")
	}
	if err := kr.VerifyIntegrity(
		apcrypto.IntegrityDomainNodeRole,
		roleBytes,
		sidecar.IntegrityTerm,
		sidecar.HMAC,
	); err != nil {
		return roleWrap(ErrRoleMismatch, err, "HMAC verification failed")
	}
	return nil
}

func MarshalSidecar(sidecar *IntegritySidecar) ([]byte, error) {
	if sidecar == nil {
		return nil, roleError(ErrRoleSidecarBad, "missing sidecar data")
	}
	data, err := json.MarshalIndent(sidecar, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal node role sidecar: %w", err)
	}
	return append(data, '\n'), nil
}

func ParseSidecar(data []byte) (*IntegritySidecar, error) {
	var sidecar IntegritySidecar
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&sidecar); err != nil {
		return nil, roleWrap(ErrRoleSidecarBad, err, "failed to parse sidecar")
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, roleWrap(ErrRoleSidecarBad, err, "failed to parse sidecar")
	}
	return &sidecar, nil
}

func LoadSidecar(path string) (*IntegritySidecar, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, roleWrap(ErrRoleSidecarMiss, err, "sidecar %s", path)
		}
		return nil, roleWrap(ErrRoleSidecarBad, err, "failed to read sidecar %s", path)
	}
	return ParseSidecar(data)
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

func roleError(kind error, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	return fmt.Errorf("%w: %w: %s", ErrRoleIntegrity, kind, msg)
}

func roleWrap(kind error, cause error, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	return fmt.Errorf("%w: %w: %s: %w", ErrRoleIntegrity, kind, msg, cause)
}
