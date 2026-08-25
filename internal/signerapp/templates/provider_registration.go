// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templates

import (
	"strings"

	"github.com/aplane-algo/aplane/internal/lsigprovider"
)

func registerProductProvider(keyType string, register func() bool) bool {
	keyType = normalizeTemplateProviderKeyType(keyType)
	if keyType == "" || register == nil {
		return false
	}
	return register()
}

// UnregisterProductProvider removes the installed-template provider for the
// one product activation set. Product callers hold the process store mutation
// lock, so there is no per-runtime reference count to reconcile.
func UnregisterProductProvider(keyType string) bool {
	keyType = normalizeTemplateProviderKeyType(keyType)
	if keyType == "" {
		return false
	}
	return lsigprovider.Unregister(keyType)
}

func normalizeTemplateProviderKeyType(keyType string) string {
	return strings.ToLower(strings.TrimSpace(keyType))
}
