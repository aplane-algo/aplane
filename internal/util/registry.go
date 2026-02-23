// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"sort"
	"sync"
)

// StringRegistry is a thread-safe registry for string-keyed values.
// It provides common registry operations with sorted key retrieval.
type StringRegistry[V any] struct {
	mu    sync.RWMutex
	items map[string]V
}

// NewStringRegistry creates a new empty registry.
func NewStringRegistry[V any]() *StringRegistry[V] {
	return &StringRegistry[V]{items: make(map[string]V)}
}

// Set stores a value by key if the key doesn't exist.
// Returns true if new key was added, false if key already existed (value not updated).
// Use Store() if you need overwrite semantics.
func (r *StringRegistry[V]) Set(key string, value V) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[key]; exists {
		return false
	}
	r.items[key] = value
	return true
}

// Get retrieves a value by key.
func (r *StringRegistry[V]) Get(key string) (V, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.items[key]
	return v, ok
}

// Has checks if a key exists.
func (r *StringRegistry[V]) Has(key string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.items[key]
	return ok
}

// Keys returns all keys, sorted alphabetically.
func (r *StringRegistry[V]) Keys() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	keys := make([]string, 0, len(r.items))
	for k := range r.items {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Values returns all values, sorted by key.
func (r *StringRegistry[V]) Values() []V {
	r.mu.RLock()
	defer r.mu.RUnlock()
	keys := make([]string, 0, len(r.items))
	for k := range r.items {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	values := make([]V, 0, len(r.items))
	for _, k := range keys {
		values = append(values, r.items[k])
	}
	return values
}
