// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadManifestRejectsInvalidRole(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(`{"schema":"aplane.backup.manifest.v1","schema_version":1,"source_node_role":"dual"}`)
	if err := os.WriteFile(filepath.Join(dir, ManifestFileName), raw, 0o600); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	_, _, err := ReadManifest(dir)
	if err == nil || !strings.Contains(err.Error(), "invalid backup manifest source_node_role") {
		t.Fatalf("ReadManifest() error = %v, want invalid role rejection", err)
	}
}
