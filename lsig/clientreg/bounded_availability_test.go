// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build !testmode

package clientreg

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/lsig/boundedaccount"
)

// aplane.bounded.v1 ships only with its operator experience. Until then a release
// must not offer it, and being listed as disabled would still let it be enabled.
func TestGeneralBoundedKeyTypeIsUnavailable(t *testing.T) {
	RegisterClient()
	entry, ok := keytypecatalog.Get(boundedaccount.KeyTypeV1)
	if !ok || entry.Availability != keytypecatalog.AvailabilityDisabled {
		t.Fatalf("catalog entry = %+v, %v; want disabled", entry, ok)
	}
	if keytypecatalog.IsLibraryVisible(boundedaccount.KeyTypeV1) {
		t.Fatal("the key type is offered in the library")
	}
	if lsigprovider.Get(boundedaccount.KeyTypeV1) != nil {
		t.Fatal("the provider is registered")
	}
}
