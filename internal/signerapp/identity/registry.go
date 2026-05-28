// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package identity

import (
	"fmt"
	"sync"
)

// Registry manages identity runtimes for the process.
// The registry lock must only be held long enough to look up or
// mutate the map; it must be released before acquiring any
// identity-internal lock or blocking on identity work.
type Registry struct {
	mu       sync.RWMutex
	runtimes map[string]*Runtime
}

// NewRegistry creates an empty identity registry.
func NewRegistry() *Registry {
	return &Registry{
		runtimes: make(map[string]*Runtime),
	}
}

// Register adds an identity runtime to the registry.
// Returns an error if the identity ID is already registered.
func (r *Registry) Register(ir *Runtime) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.runtimes[ir.id]; exists {
		return fmt.Errorf("identity already registered: %s", ir.id)
	}
	r.runtimes[ir.id] = ir
	return nil
}

// Get returns the identity runtime for the given ID, or nil if not found.
func (r *Registry) Get(id string) *Runtime {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.runtimes[id]
}

// MustGet returns the identity runtime for the given ID, or panics.
func (r *Registry) MustGet(id string) *Runtime {
	ir := r.Get(id)
	if ir == nil {
		panic(fmt.Sprintf("identity not found: %s", id))
	}
	return ir
}

// All returns a snapshot of all registered identity runtimes.
func (r *Registry) All() []*Runtime {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*Runtime, 0, len(r.runtimes))
	for _, ir := range r.runtimes {
		result = append(result, ir)
	}
	return result
}

// Count returns the number of registered identities.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.runtimes)
}

// Remove deregisters an identity runtime. The caller is responsible for
// calling Destroy() on the runtime after removal. Returns an error if
// the identity is not registered.
func (r *Registry) Remove(id string) (*Runtime, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ir, exists := r.runtimes[id]
	if !exists {
		return nil, fmt.Errorf("identity not registered: %s", id)
	}
	delete(r.runtimes, id)
	return ir, nil
}

// IDs returns a snapshot of all registered identity IDs.
func (r *Registry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.runtimes))
	for id := range r.runtimes {
		ids = append(ids, id)
	}
	return ids
}
