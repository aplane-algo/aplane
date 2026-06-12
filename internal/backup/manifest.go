// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/noderole"
)

const (
	ManifestFileName      = "manifest.json"
	ManifestSchema        = "aplane.backup.manifest.v1"
	ManifestSchemaVersion = 1
)

type Manifest struct {
	Schema         string `json:"schema"`
	SchemaVersion  int    `json:"schema_version"`
	SourceNodeRole string `json:"source_node_role"`
	CreatedAtUnix  int64  `json:"created_at_unix,omitempty"`
}

func WriteManifest(destDir string, role noderole.Role, createdAt time.Time) error {
	if _, err := noderole.ParseRole(string(role)); err != nil {
		return err
	}
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	manifest := Manifest{
		Schema:         ManifestSchema,
		SchemaVersion:  ManifestSchemaVersion,
		SourceNodeRole: string(role),
		CreatedAtUnix:  createdAt.UTC().Unix(),
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal backup manifest: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(destDir, ManifestFileName), data, fsutil.StoreFilePerm); err != nil {
		return fmt.Errorf("failed to write backup manifest: %w", err)
	}
	return nil
}

func ReadManifest(sourceRoot string) (Manifest, bool, error) {
	data, err := os.ReadFile(filepath.Join(sourceRoot, ManifestFileName))
	if err != nil {
		if os.IsNotExist(err) {
			return Manifest{}, false, nil
		}
		return Manifest{}, false, fmt.Errorf("failed to read backup manifest: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, false, fmt.Errorf("failed to parse backup manifest: %w", err)
	}
	if manifest.Schema != ManifestSchema {
		return Manifest{}, false, fmt.Errorf("unsupported backup manifest schema: %q", manifest.Schema)
	}
	if manifest.SchemaVersion != ManifestSchemaVersion {
		return Manifest{}, false, fmt.Errorf("unsupported backup manifest schema_version: %d", manifest.SchemaVersion)
	}
	if _, err := noderole.ParseRole(manifest.SourceNodeRole); err != nil {
		return Manifest{}, false, fmt.Errorf("invalid backup manifest source_node_role: %w", err)
	}
	return manifest, true, nil
}
