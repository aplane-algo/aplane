// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeperm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/fsutil"
)

const (
	// ServicePrincipalRelativePath is root-controlled installer metadata that
	// identifies the uid/gid a systemd-managed store must belong to. Numeric
	// ids are refreshed by systemd setup before every permission migration.
	ServicePrincipalRelativePath = "install/service-principal.json"
	servicePrincipalMaxBytes     = 4096
)

type servicePrincipalMetadata struct {
	SchemaVersion int `json:"schema_version"`
	UID           int `json:"uid"`
	GID           int `json:"gid"`
}

// ManagedServiceOwner resolves the expected service uid/gid from
// root-controlled installer metadata. It never trusts the store root's owner,
// because repairing that ownership is the purpose of the caller.
func ManagedServiceOwner(root string) (int, int, error) {
	file, err := openManagedServicePrincipal(root)
	if err != nil {
		return 0, 0, fmt.Errorf("open managed service principal metadata: %w", err)
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, servicePrincipalMaxBytes+1))
	if err != nil {
		return 0, 0, fmt.Errorf("read managed service principal metadata: %w", err)
	}
	if len(data) > servicePrincipalMaxBytes {
		return 0, 0, fmt.Errorf("managed service principal metadata exceeds %d bytes", servicePrincipalMaxBytes)
	}
	metadata, err := parseServicePrincipalMetadata(data)
	if err != nil {
		return 0, 0, fmt.Errorf("parse managed service principal metadata: %w", err)
	}
	return metadata.UID, metadata.GID, nil
}

func parseServicePrincipalMetadata(data []byte) (servicePrincipalMetadata, error) {
	var metadata servicePrincipalMetadata
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return metadata, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return metadata, fmt.Errorf("multiple JSON values")
		}
		return metadata, err
	}
	if metadata.SchemaVersion != 1 {
		return metadata, fmt.Errorf("unsupported schema_version %d", metadata.SchemaVersion)
	}
	if metadata.UID <= 0 {
		return metadata, fmt.Errorf("service uid must be greater than zero")
	}
	if metadata.GID < 0 {
		return metadata, fmt.Errorf("service gid must not be negative")
	}
	return metadata, nil
}

// PublishManagedMetadata records the service principal and publishes the
// managed-store marker last. Callers must hold the exclusive store lock and
// must have completed the legacy migration before calling this function.
func PublishManagedMetadata(root string, uid, gid int) error {
	if uid <= 0 || gid < 0 {
		return fmt.Errorf("invalid managed service ownership %d:%d", uid, gid)
	}
	installDir := filepath.Join(root, "install")
	if err := ensureRootControlledInstallDir(installDir, gid); err != nil {
		return err
	}
	principal, err := json.Marshal(servicePrincipalMetadata{SchemaVersion: 1, UID: uid, GID: gid})
	if err != nil {
		return fmt.Errorf("encode managed service principal metadata: %w", err)
	}
	principal = append(principal, '\n')
	if err := fsutil.WriteRootOwnedGroupReadableFileDurable(
		filepath.Join(root, ServicePrincipalRelativePath), principal, gid,
	); err != nil {
		return fmt.Errorf("publish managed service principal metadata: %w", err)
	}
	if err := fsutil.WriteServiceOwnedFileDurable(
		filepath.Join(root, ".prod"), []byte("systemd-managed\n"), uid, gid,
	); err != nil {
		return fmt.Errorf("publish managed-store marker: %w", err)
	}
	return nil
}

func ensureRootControlledInstallDir(path string, gid int) error {
	if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
		return fmt.Errorf("create install metadata directory: %w", err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect install metadata directory: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return fmt.Errorf("install metadata path is not a real directory: %s", path)
	}
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open install metadata directory: %w", err)
	}
	defer func() { _ = dir.Close() }()
	after, err := dir.Stat()
	if err != nil {
		return fmt.Errorf("inspect opened install metadata directory: %w", err)
	}
	if !after.IsDir() || !os.SameFile(before, after) {
		return fmt.Errorf("install metadata directory changed while opening: %s", path)
	}
	if err := dir.Chown(0, gid); err != nil {
		return fmt.Errorf("set install metadata directory ownership: %w", err)
	}
	if err := dir.Chmod(0o750); err != nil {
		return fmt.Errorf("set install metadata directory mode: %w", err)
	}
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync install metadata directory: %w", err)
	}
	return fsutil.SyncDir(filepath.Dir(path))
}
