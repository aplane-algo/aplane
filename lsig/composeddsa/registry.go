// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"fmt"
	"strings"
	"sync"

	"github.com/aplane-algo/aplane/internal/addressderive"
)

// AddressDeriverFactory creates an address deriver for a composed template key type.
type AddressDeriverFactory func(templateKeyType string) addressderive.Deriver

// BaseRegistration describes a DSA provider that may be used as a composed
// template base.
type BaseRegistration struct {
	BaseKeyType       string
	FamilyName        string
	Version           int
	Ops               DSAOps
	NewAddressDeriver AddressDeriverFactory
}

var baseRegistry = struct {
	mu    sync.RWMutex
	bases map[string]BaseRegistration
}{
	bases: make(map[string]BaseRegistration),
}

// RegisterBase marks a DSA key type as eligible for composed templates.
func RegisterBase(reg BaseRegistration) {
	normalized, err := normalizeBaseRegistration(reg)
	if err != nil {
		panic(err)
	}
	baseRegistry.mu.Lock()
	defer baseRegistry.mu.Unlock()
	baseRegistry.bases[normalized.BaseKeyType] = normalized
}

// LookupBase returns the registration for a composable DSA base key type.
func LookupBase(baseKeyType string) (BaseRegistration, bool) {
	key := strings.ToLower(strings.TrimSpace(baseKeyType))
	baseRegistry.mu.RLock()
	defer baseRegistry.mu.RUnlock()
	reg, ok := baseRegistry.bases[key]
	return reg, ok
}

// IsBaseRegistered reports whether a base key type is registered as composable.
func IsBaseRegistered(baseKeyType string) bool {
	_, ok := LookupBase(baseKeyType)
	return ok
}

func normalizeBaseRegistration(reg BaseRegistration) (BaseRegistration, error) {
	reg.BaseKeyType = strings.ToLower(strings.TrimSpace(reg.BaseKeyType))
	reg.FamilyName = strings.TrimSpace(reg.FamilyName)
	if reg.BaseKeyType == "" {
		return BaseRegistration{}, fmt.Errorf("composeddsa: base key type is required")
	}
	if reg.FamilyName == "" {
		return BaseRegistration{}, fmt.Errorf("composeddsa: family name is required for %s", reg.BaseKeyType)
	}
	if reg.Version < 1 {
		return BaseRegistration{}, fmt.Errorf("composeddsa: version must be >= 1 for %s", reg.BaseKeyType)
	}
	if reg.Ops == nil {
		return BaseRegistration{}, fmt.Errorf("composeddsa: DSA ops are required for %s", reg.BaseKeyType)
	}
	if reg.NewAddressDeriver == nil {
		return BaseRegistration{}, fmt.Errorf("composeddsa: address deriver factory is required for %s", reg.BaseKeyType)
	}
	return reg, nil
}
