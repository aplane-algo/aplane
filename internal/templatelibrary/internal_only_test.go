// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templatelibrary

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
)

func TestInternalProviderCannotBeListedOrEnabled(t *testing.T) {
	const keyType = "test.internal-library.v1"
	keytypecatalog.Register(keytypecatalog.Entry{KeyType: keyType, Family: "test.internal-library", Availability: keytypecatalog.AvailabilityInternalOnly})
	lsigprovider.Register(stubProvider{keyType: keyType})
	t.Cleanup(func() { lsigprovider.Unregister(keyType) })
	paths := newLibraryTestPaths(t)
	for _, enabled := range []bool{false, true} {
		if enabled {
			if err := keytypestate.Put(paths, keytypestate.Record{KeyType: keyType, Source: keytypestate.SourceCompiled, State: keytypestate.StateEnabled}); err != nil {
				t.Fatal(err)
			}
		}
		items, err := List(paths)
		if err != nil {
			t.Fatal(err)
		}
		if findLibraryItem(items, keyType) != nil {
			t.Fatal("internal provider exposed in library")
		}
		if _, err := ActivateCompiledProvider(paths, keyType); err == nil || !strings.Contains(err.Error(), "internal-only") {
			t.Fatalf("ActivateCompiledProvider() = %v", err)
		}
		if _, exists, err := keytypestate.Get(paths, keyType); err != nil || exists != enabled {
			t.Fatalf("refusal changed stored enablement: exists=%v, err=%v", exists, err)
		}
	}
}
