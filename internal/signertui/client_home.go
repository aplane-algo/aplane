// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/aplane-algo/aplane/internal/addressbook"
	"github.com/aplane-algo/aplane/internal/cache"
)

func splitAddressListValue(value string) []string {
	if value == "" {
		return nil
	}

	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func buildReadOnlyAddressResolver(dataDir string) (*addressbook.Resolver, error) {
	aliasCache := cache.AliasCache{Aliases: make(map[string]string)}
	setCache := cache.SetCache{Sets: make(map[string][]string)}

	if dataDir == "" {
		return addressbook.NewResolver(&aliasCache, &setCache), nil
	}

	cacheDir := filepath.Join(dataDir, "cache")
	keyPath := filepath.Join(cacheDir, ".cache_key")
	key, err := os.ReadFile(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return addressbook.NewResolver(&aliasCache, &setCache), nil
		}
		return nil, fmt.Errorf("failed to read cache key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid cache key length: expected 32 bytes, got %d", len(key))
	}

	aliasPath := filepath.Join(cacheDir, "alias_cache.json")
	if _, err := os.Stat(aliasPath); err == nil {
		if err := cache.LoadSignedCache(aliasPath, key, &aliasCache); err != nil {
			return nil, fmt.Errorf("failed to load alias cache: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to stat alias cache: %w", err)
	}

	setPath := filepath.Join(cacheDir, "set_cache.json")
	if _, err := os.Stat(setPath); err == nil {
		if err := cache.LoadSignedCache(setPath, key, &setCache); err != nil {
			return nil, fmt.Errorf("failed to load set cache: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to stat set cache: %w", err)
	}

	return addressbook.NewResolver(&aliasCache, &setCache), nil
}

func resolveAddressListValue(dataDir, value string) (string, error) {
	entries := splitAddressListValue(value)
	if len(entries) == 0 {
		return "", nil
	}
	for i, entry := range entries {
		if strings.HasPrefix(entry, "@") && len(entry) > 1 {
			entries[i] = "@" + strings.ToLower(entry[1:])
		}
	}

	resolver, err := buildReadOnlyAddressResolver(dataDir)
	if err != nil {
		return "", err
	}
	addresses, err := resolver.ResolveList(entries)
	if err != nil {
		return "", err
	}
	return strings.Join(addresses, ","), nil
}
