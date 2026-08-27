// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const deletedArchiveMaxPruneSelection = 256

type DeletedArchiveEntry struct {
	Path         string
	EncodedBytes int64
}

type DeletedArchivePruneResult struct {
	Path          string
	EncodedBytes  int64
	AlreadyAbsent bool
}

// ListDeletedArchive returns canonical generation-relative names. It never
// exposes a retained generation and rejects an over-limit selected archive.
func ListDeletedArchive(gen storepaths.GenPaths) ([]DeletedArchiveEntry, DeletedArchiveUsage, error) {
	usage, err := InspectDeletedArchive(gen)
	if err != nil {
		return nil, usage, err
	}
	var result []DeletedArchiveEntry
	for _, namespace := range []struct{ relative, dir string }{
		{"deleted/keys", gen.DeletedKeysDir()},
		{"deleted/keytypes", gen.DeletedKeyTypeRecordsDir()},
	} {
		entries, err := os.ReadDir(namespace.dir)
		if err != nil {
			return nil, usage, err
		}
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				return nil, usage, err
			}
			result = append(result, DeletedArchiveEntry{
				Path:         filepath.ToSlash(filepath.Join(namespace.relative, entry.Name())),
				EncodedBytes: info.Size(),
			})
		}
	}
	slices.SortFunc(result, func(a, b DeletedArchiveEntry) int { return strings.Compare(a.Path, b.Path) })
	return result, usage, nil
}

// PruneDeletedArchive irreversibly removes explicitly selected entries only
// from the authenticated selected generation. The caller holds the mutation
// lock and enforces authorization, confirmation, and durable audit.
func PruneDeletedArchive(gen storepaths.GenPaths, relativePaths []string) ([]DeletedArchivePruneResult, error) {
	if len(relativePaths) == 0 {
		return nil, fmt.Errorf("archive prune requires at least one entry")
	}
	if len(relativePaths) > deletedArchiveMaxPruneSelection {
		return nil, fmt.Errorf("archive prune selection exceeds limit %d", deletedArchiveMaxPruneSelection)
	}
	seen := make(map[string]struct{}, len(relativePaths))
	targets := make([]string, len(relativePaths))
	for i, relative := range relativePaths {
		clean, err := validateDeletedArchiveRelativePath(relative)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[clean]; duplicate {
			return nil, fmt.Errorf("duplicate archive entry %s", clean)
		}
		seen[clean] = struct{}{}
		targets[i] = clean
	}

	// Prevalidate the entire selection before deleting the first member.
	results := make([]DeletedArchivePruneResult, len(targets))
	for i, relative := range targets {
		result := DeletedArchivePruneResult{Path: relative}
		path := filepath.Join(gen.Dir(), filepath.FromSlash(relative))
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			result.AlreadyAbsent = true
			results[i] = result
			continue
		}
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("archive prune target is not a regular file: %s", relative)
		}
		result.EncodedBytes = info.Size()
		results[i] = result
	}
	for i, relative := range targets {
		if results[i].AlreadyAbsent {
			continue
		}
		path := filepath.Join(gen.Dir(), filepath.FromSlash(relative))
		if err := fsutil.RemoveDurable(path); err != nil {
			return results[:i], fmt.Errorf("prune archive entry %s: %w", relative, err)
		}
	}
	return results, nil
}

func validateDeletedArchiveRelativePath(relative string) (string, error) {
	if relative == "" || strings.ContainsRune(relative, 0) || strings.Contains(relative, "\\") {
		return "", fmt.Errorf("invalid archive entry %q", relative)
	}
	clean := filepath.ToSlash(filepath.Clean(relative))
	if clean != relative || strings.Contains(clean, "..") {
		return "", fmt.Errorf("invalid archive entry %q", relative)
	}
	dir, base := filepath.ToSlash(filepath.Dir(clean)), filepath.Base(clean)
	if base == "." || base == "" {
		return "", fmt.Errorf("invalid archive entry %q", relative)
	}
	switch dir {
	case "deleted/keys":
		if !strings.HasSuffix(base, ".key") && !strings.HasSuffix(base, ".sen") {
			return "", fmt.Errorf("invalid deleted credential entry %q", relative)
		}
	case "deleted/keytypes":
		if !strings.HasSuffix(base, ".template") {
			return "", fmt.Errorf("invalid deleted template entry %q", relative)
		}
	default:
		return "", fmt.Errorf("archive entry is outside the closed deleted namespaces: %q", relative)
	}
	return clean, nil
}
