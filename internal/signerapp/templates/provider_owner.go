// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templates

import (
	"strings"
	"sync"

	"github.com/aplane-algo/aplane/internal/lsigprovider"
)

var templateProviderOwners = &providerOwners{
	ownersByKeyType: make(map[string]map[string]struct{}),
}

// providerOwners serializes identity ownership of process-global template
// providers. Production callers acquire the identity mutation lock before this
// lock, and this lock may call into lsigprovider.registerMu.
type providerOwners struct {
	mu              sync.Mutex
	ownersByKeyType map[string]map[string]struct{}
}

func recordProviderOwner(identityID, keyType string) {
	templateProviderOwners.record(identityID, keyType)
}

func registerProviderForOwner(identityID, keyType string, register func() bool) bool {
	return templateProviderOwners.register(identityID, keyType, register)
}

// ReleaseProviderOwner releases one identity's reference to an installed
// template provider. It unregisters the process-global provider only when no
// identities still own that key type.
func ReleaseProviderOwner(identityID, keyType string) bool {
	return templateProviderOwners.release(identityID, keyType)
}

func (p *providerOwners) record(identityID, keyType string) {
	identityID = strings.TrimSpace(identityID)
	keyType = normalizeTemplateProviderKeyType(keyType)
	if identityID == "" || keyType == "" {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.recordLocked(identityID, keyType)
}

func (p *providerOwners) register(identityID, keyType string, register func() bool) bool {
	identityID = strings.TrimSpace(identityID)
	keyType = normalizeTemplateProviderKeyType(keyType)
	if identityID == "" || keyType == "" || register == nil {
		return false
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if !register() {
		return false
	}
	p.recordLocked(identityID, keyType)
	return true
}

func (p *providerOwners) release(identityID, keyType string) bool {
	identityID = strings.TrimSpace(identityID)
	keyType = normalizeTemplateProviderKeyType(keyType)
	if identityID == "" || keyType == "" {
		return false
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	owners := p.ownersByKeyType[keyType]
	if len(owners) == 0 {
		return false
	}
	delete(owners, identityID)
	if len(owners) > 0 {
		return false
	}
	delete(p.ownersByKeyType, keyType)
	return lsigprovider.Unregister(keyType)
}

func (p *providerOwners) recordLocked(identityID, keyType string) {
	owners := p.ownersByKeyType[keyType]
	if owners == nil {
		owners = make(map[string]struct{})
		p.ownersByKeyType[keyType] = owners
	}
	owners[identityID] = struct{}{}
}

func normalizeTemplateProviderKeyType(keyType string) string {
	return strings.ToLower(strings.TrimSpace(keyType))
}
