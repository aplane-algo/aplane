// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build testmode

package clientreg

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/lsig/boundedaccount"
)

// buildLibraryVisibleKeyTypes lists library key types that depend on the build.
func buildLibraryVisibleKeyTypes() []string {
	return []string{boundedaccount.KeyTypeV1}
}

// The harness builds with this tag to reach the key type before it ships, so the
// tag has to actually register it.
func TestGeneralBoundedKeyTypeIsAvailableUnderTestmode(t *testing.T) {
	RegisterClient()
	if !keytypecatalog.IsLibraryVisible(boundedaccount.KeyTypeV1) {
		t.Fatal("the key type is not offered in the library")
	}
	if lsigprovider.Get(boundedaccount.KeyTypeV1) == nil {
		t.Fatal("the provider is not registered")
	}
}
