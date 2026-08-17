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

// TestSentryCatalogSubtractionDoesNotRegrow pins the separation between the
// signer-owned generation catalog and client-owned live routing discovery.
func TestSentryCatalogSubtractionDoesNotRegrow(t *testing.T) {
	root := filepath.Join("..", "..")
	legacyAdapters := map[string]bool{
		filepath.Clean(filepath.Join(root, "internal", "config", "client_endpoints_v1.go")):         true,
		filepath.Clean(filepath.Join(root, "internal", "sentry", "sentryrefs", "sentryrefs_v1.go")): true,
	}
	forbiddenEverywhere := []string{
		"SentryEndpoints map[",
		"SourceClientDiscovery",
		"SyncedReferenceName",
		"AdminSyncSentryReferences",
		"SentryReferenceCandidate",
		"SyncDiscovered",
		"DiscoveredRecord",
		"ActionSentriesSync",
		`"/admin/sentries/sync"`,
		`"sentries.sync"`,
		`"sync-sentries"`,
		`"endpoints sentries"`,
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
					t.Errorf("%s contains retired sentry catalog shape %q", path, shape)
				}
			}
			if !legacyAdapters[filepath.Clean(path)] {
				for _, shape := range []string{"PublishedSentries", `"published_sentries"`, `"client_discovery"`} {
					if strings.Contains(text, shape) {
						t.Errorf("%s contains legacy sentry discovery persistence outside its read adapter: %q", path, shape)
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
	for _, fixture := range []string{"admin_sync_sentry_references_request.json", "admin_sync_sentry_references_response.json"} {
		if strings.Contains(string(manifest), fixture) {
			t.Errorf("contract manifest contains retired fixture %q", fixture)
		}
	}
}
