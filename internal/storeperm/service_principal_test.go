// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeperm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/fsutil"
)

func TestParseServicePrincipalMetadata(t *testing.T) {
	metadata, err := parseServicePrincipalMetadata([]byte(`{"schema_version":1,"uid":123,"gid":456}`))
	if err != nil {
		t.Fatal(err)
	}
	if metadata.UID != 123 || metadata.GID != 456 {
		t.Fatalf("metadata = %#v, want uid 123 gid 456", metadata)
	}
}

func TestParseServicePrincipalMetadataRejectsUnsafeValues(t *testing.T) {
	for _, data := range []string{
		`{"schema_version":2,"uid":123,"gid":456}`,
		`{"schema_version":1,"uid":0,"gid":456}`,
		`{"schema_version":1,"uid":123,"gid":-1}`,
		`{"schema_version":1,"uid":123,"gid":456,"extra":true}`,
		`{"schema_version":1,"uid":123,"gid":456} {}`,
	} {
		if _, err := parseServicePrincipalMetadata([]byte(data)); err == nil {
			t.Fatalf("parseServicePrincipalMetadata(%s) error = nil", data)
		}
	}
}

func TestPublishManagedMetadata(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root ownership changes")
	}
	root := t.TempDir()
	if err := PublishManagedMetadata(root, 123, 456); err != nil {
		t.Fatal(err)
	}
	uid, gid, err := ManagedServiceOwner(root)
	if err != nil {
		t.Fatal(err)
	}
	if uid != 123 || gid != 456 {
		t.Fatalf("managed owner = %d:%d, want 123:456", uid, gid)
	}
	marker, err := os.Stat(filepath.Join(root, ".prod"))
	if err != nil {
		t.Fatal(err)
	}
	markerUID, markerGID, ok := fsutil.FileOwnership(marker)
	if !ok || markerUID != 123 || markerGID != 456 || marker.Mode().Perm() != 0o600 {
		t.Fatalf("marker ownership/mode = %d:%d %04o", markerUID, markerGID, marker.Mode().Perm())
	}
}
