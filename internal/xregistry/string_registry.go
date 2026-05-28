// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package xregistry provides small keyed registries used by internal package
// registrars.
package xregistry

import (
	"sort"
	"sync"
)

type StringRegistry[V any] struct {
	mu    sync.RWMutex
	items map[string]V
}

func NewStringRegistry[V any]() *StringRegistry[V] {
	return &StringRegistry[V]{items: make(map[string]V)}
}

func (r *StringRegistry[V]) Set(key string, value V) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[key]; exists {
		return false
	}
	r.items[key] = value
	return true
}

func (r *StringRegistry[V]) Get(key string) (V, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.items[key]
	return v, ok
}

func (r *StringRegistry[V]) Has(key string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.items[key]
	return ok
}

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
