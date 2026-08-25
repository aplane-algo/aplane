// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package keytypecatalog records product-level visibility for compiled key
// types. Provider registries describe what the binary can execute; this catalog
// describes which compiled key types are default-visible or library-visible.
package keytypecatalog

import (
	"fmt"
	"sort"
	"sync"
)

type Availability string

const (
	// AvailabilityDefaultEnabled means every identity may see and create this
	// key type without an product-store state record.
	AvailabilityDefaultEnabled Availability = "default_enabled"

	// AvailabilityLibrary means the provider is registered as binary capability
	// but hidden from normal generation/import until identity opt-in state exists.
	AvailabilityLibrary Availability = "library"

	// AvailabilityDisabled means the provider may be compiled in but should not
	// be registered or exposed by the runtime path that owns the catalog entry.
	AvailabilityDisabled Availability = "disabled"
)

type Entry struct {
	KeyType      string
	Family       string
	Availability Availability
}

var (
	mu      sync.RWMutex
	entries = map[string]Entry{}
)

// Register records catalog metadata. Re-registering the same entry is
// idempotent; registering conflicting metadata for a key type panics.
func Register(entry Entry) {
	normalized, err := normalizeEntry(entry)
	if err != nil {
		panic(err.Error())
	}

	mu.Lock()
	defer mu.Unlock()

	key := normalized.KeyType
	if existing, ok := entries[key]; ok {
		if existing != normalized {
			panic(fmt.Sprintf("conflicting key type catalog registration for %s", key))
		}
		return
	}
	entries[key] = normalized
}

func Get(keyType string) (Entry, bool) {
	mu.RLock()
	defer mu.RUnlock()

	entry, ok := entries[Canonicalize(keyType)]
	return entry, ok
}

func LibraryVisible() []Entry {
	return filter(func(entry Entry) bool {
		return entry.Availability == AvailabilityLibrary
	})
}

func DefaultEnabled() []Entry {
	return filter(func(entry Entry) bool {
		return entry.Availability == AvailabilityDefaultEnabled
	})
}

// IsDefaultEnabled reports whether a cataloged key type is visible by default.
// Missing catalog entries are not default-enabled; compiled key types must be
// cataloged explicitly.
func IsDefaultEnabled(keyType string) bool {
	entry, ok := Get(keyType)
	if !ok {
		return false
	}
	return entry.Availability == AvailabilityDefaultEnabled
}

func IsLibraryVisible(keyType string) bool {
	entry, ok := Get(keyType)
	return ok && entry.Availability == AvailabilityLibrary
}

func filter(include func(Entry) bool) []Entry {
	mu.RLock()
	defer mu.RUnlock()

	result := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		if include(entry) {
			result = append(result, entry)
		}
	}
	sortEntries(result)
	return result
}

func normalizeEntry(entry Entry) (Entry, error) {
	entry.KeyType = Canonicalize(entry.KeyType)
	entry.Family = Canonicalize(entry.Family)
	if entry.KeyType == "" {
		return Entry{}, fmt.Errorf("key type catalog entry has empty key type")
	}
	if entry.Family == "" {
		return Entry{}, fmt.Errorf("key type catalog entry %s has empty family", entry.KeyType)
	}
	switch entry.Availability {
	case AvailabilityDefaultEnabled, AvailabilityLibrary, AvailabilityDisabled:
		return entry, nil
	default:
		return Entry{}, fmt.Errorf("key type catalog entry %s has invalid availability %q", entry.KeyType, entry.Availability)
	}
}

func sortEntries(items []Entry) {
	sort.Slice(items, func(i, j int) bool {
		return items[i].KeyType < items[j].KeyType
	})
}
