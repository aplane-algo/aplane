// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCosignerCatalogSubtractionDoesNotRegrow pins the separation between the
// signer-owned generation catalog and client-owned live routing discovery.
func TestCosignerCatalogSubtractionDoesNotRegrow(t *testing.T) {
	root := filepath.Join("..", "..")
	// The v1 read adapters are deleted: no reader of pre-v2 cosigner or
	// endpoint data remains.
	for _, retired := range []string{
		filepath.Join(root, "internal", "config", "client_endpoints_v1.go"),
		filepath.Join(root, "internal", "cosigner", "cosignerrefs", "cosignerrefs_v1.go"),
	} {
		if _, err := os.Stat(retired); !os.IsNotExist(err) {
			t.Errorf("%s returned; pre-v2 cosigner and endpoint data is not read", retired)
		}
	}
	forbiddenEverywhere := []string{
		"CosignerEndpoints CosignerEndpointConfigs",
		"type CosignerEndpointConfigs",
		"ClientEndpointPublishedCosigner",
		"SourceClientDiscovery",
		"SyncedReferenceName",
		"AdminSyncCosignerReferences",
		"CosignerReferenceCandidate",
		"SyncDiscovered",
		"DiscoveredRecord",
		"ActionCosignersSync",
		`"/admin/cosigners/sync"`,
		`"cosigners.sync"`,
		`"sync-cosigners"`,
		`"endpoints cosigners"`,
	}

	for _, subtree := range []string{"cmd", "internal", "pkg"} {
		err := filepath.WalkDir(filepath.Join(root, subtree), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			text := string(data)
			for _, shape := range forbiddenEverywhere {
				if strings.Contains(text, shape) {
					t.Errorf("%s contains retired cosigner catalog shape %q", path, shape)
				}
			}
			for _, shape := range []string{"PublishedCosigners", `"published_cosigners"`, `"client_discovery"`} {
				if strings.Contains(text, shape) {
					t.Errorf("%s contains legacy cosigner discovery persistence: %q", path, shape)
				}
			}
			if strings.Contains(filepath.ToSlash(path), "/internal/cosigner/cosignerrefs/") {
				for _, shape := range []string{`json:"source`, `json:"endpoint_alias`, `json:"last_seen_at`, `json:"synced_at`} {
					if strings.Contains(text, shape) {
						t.Errorf("%s contains retired v1 cosigner-reference field %q", path, shape)
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	manifest, err := os.ReadFile(filepath.Join(root, "test", "contracts", "signerapi", "fixture_manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []string{"admin_sync_cosigners_request.json", "admin_sync_cosigners_response.json"} {
		if strings.Contains(string(manifest), fixture) {
			t.Errorf("contract manifest contains retired fixture %q", fixture)
		}
	}
}
