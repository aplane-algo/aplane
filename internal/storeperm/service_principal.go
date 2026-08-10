// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeperm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
