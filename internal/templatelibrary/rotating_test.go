// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templatelibrary

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	rotatingsignerreg "github.com/aplane-algo/aplane/lsig/rotatinghybrid/signerreg"
)

func TestLibraryListsRegisteredRotatingKeyType(t *testing.T) {
	keytypecatalog.Register(keytypecatalog.Entry{
		KeyType:      rotatingkey.RotatingHybridV1,
		Family:       rotatingkey.RotatingHybridV1,
		Availability: keytypecatalog.AvailabilityLibrary,
	})
	rotatingsignerreg.Register()

	paths := newLibraryTestPaths(t)
	items, err := List(paths)
	if err != nil {
		t.Fatal(err)
	}
	item := findLibraryItem(items, rotatingkey.RotatingHybridV1)
	if item == nil {
		t.Fatal("rotating key type missing from the library")
	}
	if item.Invalid != "" {
		t.Fatalf("rotating key type listed as invalid: %s", item.Invalid)
	}
	if item.DisplayName != rotatingkey.RotatingDisplayName || len(item.Parameters) != 1 || item.Parameters[0].Name != rotatingkey.RotatingNetworkParameter {
		t.Fatalf("library item = %+v", *item)
	}
	if _, err := ActivateCompiledProvider(paths, rotatingkey.RotatingHybridV1); err != nil {
		t.Fatalf("enable: %v", err)
	}
}

func TestLibraryStillFlagsUnregisteredCatalogEntry(t *testing.T) {
	const keyType = "aplane.unregistered-library-test.v1"
	keytypecatalog.Register(keytypecatalog.Entry{
		KeyType:      keyType,
		Family:       "aplane.unregistered-library-test",
		Availability: keytypecatalog.AvailabilityLibrary,
	})
	items, err := List(newLibraryTestPaths(t))
	if err != nil {
		t.Fatal(err)
	}
	if item := findLibraryItem(items, keyType); item == nil || item.Invalid == "" {
		t.Fatalf("unregistered catalog entry = %+v, want invalid", item)
	}
}
