// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package noderole

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const (
	IntegritySidecarVersion = 1
	IntegrityAlgorithm      = "hmac-sha256"
	IntegrityKeyID          = "keystore-master-hkdf-node-role-v1"
)

type IntegritySidecar struct {
	Version      int    `json:"version"`
	Algorithm    string `json:"algorithm"`
	KeyID        string `json:"key_id"`
	HMAC         string `json:"hmac"`
	NodeSHA256   string `json:"node_sha256,omitempty"`
	SignedAtUnix int64  `json:"signed_at_unix,omitempty"`
	NodeMTimeNS  int64  `json:"node_mtime_ns,omitempty"`
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

func SaveIdentitySidecarWithMasterKey(paths storepaths.Paths, identityID string, roleBytes, masterKey []byte, signedAt time.Time) error {
	key, err := apcrypto.DeriveNodeRoleIntegrityKey(masterKey)
	if err != nil {
		return err
	}
	defer apcrypto.ZeroBytes(key)
	return SaveIdentitySidecar(paths, identityID, roleBytes, key, signedAt)
}

func SaveIdentitySidecar(paths storepaths.Paths, identityID string, roleBytes, key []byte, signedAt time.Time) error {
	if _, err := ParseDocument(roleBytes); err != nil {
		return err
	}
	info, err := os.Stat(paths.NodeRolePath())
	if err != nil {
		return fmt.Errorf("failed to stat node role %s: %w", paths.NodeRolePath(), err)
	}
	sidecar, err := Sign(roleBytes, key, signedAt, info.ModTime().UnixNano())
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

func LoadAndVerifyWithMasterKey(paths storepaths.Paths, identityID string, masterKey []byte) (Document, error) {
	key, err := apcrypto.DeriveNodeRoleIntegrityKey(masterKey)
	if err != nil {
		return Document{}, err
	}
	defer apcrypto.ZeroBytes(key)
	return LoadAndVerify(paths, identityID, key)
}

func LoadAndVerify(paths storepaths.Paths, identityID string, key []byte) (Document, error) {
	doc, roleBytes, err := Load(paths)
	if err != nil {
		return Document{}, err
	}
	sidecar, err := LoadSidecar(paths.NodeRoleIntegritySidecar(identityID))
	if err != nil {
		return Document{}, err
	}
	if err := Verify(roleBytes, sidecar, key); err != nil {
		return Document{}, err
	}
	return doc, nil
}

func Sign(roleBytes, key []byte, signedAt time.Time, nodeMTimeNS int64) (*IntegritySidecar, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	if signedAt.IsZero() {
		signedAt = time.Now()
	}
	sum := sha256.Sum256(roleBytes)
	return &IntegritySidecar{
		Version:      IntegritySidecarVersion,
		Algorithm:    IntegrityAlgorithm,
		KeyID:        IntegrityKeyID,
		HMAC:         computeHMAC(roleBytes, key),
		NodeSHA256:   hex.EncodeToString(sum[:]),
		SignedAtUnix: signedAt.UTC().Unix(),
		NodeMTimeNS:  nodeMTimeNS,
	}, nil
}

func Verify(roleBytes []byte, sidecar *IntegritySidecar, key []byte) error {
	if err := validateKey(key); err != nil {
		return err
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
	got, err := hex.DecodeString(sidecar.HMAC)
	if err != nil {
		return roleWrap(ErrRoleSidecarBad, err, "invalid hmac encoding")
	}
	expectedHex := computeHMAC(roleBytes, key)
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		return roleWrap(ErrRoleSidecarBad, err, "internal hmac encoding failure")
	}
	if !hmac.Equal(expected, got) {
		return roleError(ErrRoleMismatch, "hmac mismatch")
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
	if err := json.Unmarshal(data, &sidecar); err != nil {
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

func computeHMAC(roleBytes, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(roleBytes)
	return hex.EncodeToString(mac.Sum(nil))
}

func validateKey(key []byte) error {
	if len(key) != apcrypto.NodeRoleIntegrityKeyLength {
		return roleError(ErrRoleKeyInvalid, "expected %d bytes, got %d", apcrypto.NodeRoleIntegrityKeyLength, len(key))
	}
	return nil
}

func roleError(kind error, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	return fmt.Errorf("%w: %w: %s", ErrRoleIntegrity, kind, msg)
}

func roleWrap(kind error, cause error, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	return fmt.Errorf("%w: %w: %s: %w", ErrRoleIntegrity, kind, msg, cause)
}
