// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package noderole

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/integritysidecar"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const IntegrityKeyID = "keystore-master-hkdf-node-role-v1"

var nodeRoleSidecar = integritysidecar.Spec{
	Domain: apcrypto.IntegrityDomainNodeRole,
	KeyID:  IntegrityKeyID,
	Name:   "node role",
	Errors: integritysidecar.Errors{
		Check:       ErrRoleIntegrity,
		Bad:         ErrRoleSidecarBad,
		Missing:     ErrRoleSidecarMiss,
		Unsupported: ErrRoleUnsupported,
		Mismatch:    ErrRoleMismatch,
	},
}

// IntegritySidecar authenticates the node role file. Fields beyond the
// embedded security header are diagnostic.
type IntegritySidecar struct {
	integritysidecar.Header
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

// SaveGenerationSidecarWithKeyring authenticates the immutable data-root node
// role into one already-resolved generation.
func SaveGenerationSidecarWithKeyring(paths storepaths.Paths, active storepaths.ActivePaths, roleBytes []byte, kr *apcrypto.Keyring, signedAt time.Time) error {
	return saveSidecarAtPath(paths, active.NodeRoleIntegritySidecar(), roleBytes, kr, signedAt)
}

func saveSidecarAtPath(paths storepaths.Paths, sidecarPath string, roleBytes []byte, kr *apcrypto.Keyring, signedAt time.Time) error {
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
	if err := fsutil.MkdirAllPrivate(filepath.Dir(sidecarPath)); err != nil {
		return fmt.Errorf("failed to create node role sidecar directory: %w", err)
	}
	if err := fsutil.WriteFile(sidecarPath, sidecarBytes); err != nil {
		return fmt.Errorf("failed to write node role integrity sidecar %s: %w", sidecarPath, err)
	}
	return nil
}

// LoadAndVerifyGenerationWithKeyring verifies the immutable data-root node
// role against the sidecar in one already-resolved generation.
func LoadAndVerifyGenerationWithKeyring(paths storepaths.Paths, active storepaths.ActivePaths, kr *apcrypto.Keyring) (Document, error) {
	return loadAndVerifyAtPath(paths, active.NodeRoleIntegritySidecar(), kr)
}

func loadAndVerifyAtPath(paths storepaths.Paths, sidecarPath string, kr *apcrypto.Keyring) (Document, error) {
	doc, roleBytes, err := Load(paths)
	if err != nil {
		return Document{}, err
	}
	sidecar, err := LoadSidecar(sidecarPath)
	if err != nil {
		return Document{}, err
	}
	if err := Verify(roleBytes, sidecar, kr); err != nil {
		return Document{}, err
	}
	return doc, nil
}

func Sign(roleBytes []byte, kr *apcrypto.Keyring, signedAt time.Time, nodeMTimeNS int64) (*IntegritySidecar, error) {
	header, err := nodeRoleSidecar.Sign(roleBytes, kr)
	if err != nil {
		return nil, err
	}
	if signedAt.IsZero() {
		signedAt = time.Now()
	}
	sum := sha256.Sum256(roleBytes)
	return &IntegritySidecar{
		Header:       header,
		NodeSHA256:   hex.EncodeToString(sum[:]),
		SignedAtUnix: signedAt.UTC().Unix(),
		NodeMTimeNS:  nodeMTimeNS,
	}, nil
}

func Verify(roleBytes []byte, sidecar *IntegritySidecar, kr *apcrypto.Keyring) error {
	var header *integritysidecar.Header
	if sidecar != nil {
		header = &sidecar.Header
	}
	return nodeRoleSidecar.Verify(roleBytes, header, kr)
}

func MarshalSidecar(sidecar *IntegritySidecar) ([]byte, error) {
	if sidecar == nil {
		return nil, roleError(ErrRoleSidecarBad, "missing sidecar data")
	}
	return nodeRoleSidecar.Marshal(sidecar)
}

func ParseSidecar(data []byte) (*IntegritySidecar, error) {
	var sidecar IntegritySidecar
	if err := nodeRoleSidecar.Parse(data, &sidecar); err != nil {
		return nil, err
	}
	return &sidecar, nil
}

func LoadSidecar(path string) (*IntegritySidecar, error) {
	var sidecar IntegritySidecar
	if err := nodeRoleSidecar.Load(path, &sidecar); err != nil {
		return nil, err
	}
	return &sidecar, nil
}

func roleError(kind error, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	return fmt.Errorf("%w: %w: %s", ErrRoleIntegrity, kind, msg)
}

func roleWrap(kind error, cause error, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	return fmt.Errorf("%w: %w: %s: %w", ErrRoleIntegrity, kind, msg, cause)
}
