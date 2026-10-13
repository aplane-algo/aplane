// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templatelibrary

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	rotatingsignerreg "github.com/aplane-algo/aplane/lsig/rotatinghybrid/signerreg"
	rotatingwotssignerreg "github.com/aplane-algo/aplane/lsig/rotatingwots/signerreg"
)

func TestLibraryListsRegisteredRotatingKeyTypes(t *testing.T) {
	for _, keyType := range rotatingkey.KeyTypes() {
		profile, _ := rotatingkey.Lookup(keyType)
		keytypecatalog.Register(keytypecatalog.Entry{
			KeyType:      keyType,
			Family:       profile.Family,
			Availability: keytypecatalog.AvailabilityLibrary,
		})
	}
	rotatingsignerreg.Register()
	rotatingwotssignerreg.Register()

	paths := newLibraryTestPaths(t)
	items, err := List(paths)
	if err != nil {
		t.Fatal(err)
	}
	for _, keyType := range rotatingkey.KeyTypes() {
		profile, _ := rotatingkey.Lookup(keyType)
		item := findLibraryItem(items, keyType)
		if item == nil {
			t.Fatalf("%s missing from the library", keyType)
		}
		if item.Invalid != "" {
			t.Fatalf("%s listed as invalid: %s", keyType, item.Invalid)
		}
		if item.DisplayName != profile.DisplayName || len(item.Parameters) != 1 || item.Parameters[0].Name != rotatingkey.RotatingNetworkParameter {
			t.Fatalf("library item = %+v", *item)
		}
		if _, err := ActivateCompiledProvider(paths, keyType); err != nil {
			t.Fatalf("enable %s: %v", keyType, err)
		}
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
