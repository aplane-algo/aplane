// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypecatalog

import "testing"

func TestRegisterAndQueryAvailability(t *testing.T) {
	entry := Entry{
		KeyType:      "Catalog-Test-v1",
		Family:       "Catalog-Test",
		Availability: AvailabilityLibrary,
	}
	unregisterForTest(t, entry.KeyType)
	Register(entry)
	Register(entry)

	got, ok := Get("catalog-test-v1")
	if !ok {
		t.Fatal("Get() did not find registered entry")
	}
	if got.KeyType != "catalog-test-v1" {
		t.Fatalf("KeyType = %q, want normalized catalog-test-v1", got.KeyType)
	}
	if IsDefaultEnabled("catalog-test-v1") {
		t.Fatal("library-visible entry should not be default-enabled")
	}
	if !IsLibraryVisible("catalog-test-v1") {
		t.Fatal("library-visible entry not reported as library-visible")
	}
}

func TestMissingEntryIsNotDefaultEnabled(t *testing.T) {
	if IsDefaultEnabled("uncataloged-test-v1") {
		t.Fatal("missing catalog entries should not be default-enabled")
	}
	if IsLibraryVisible("uncataloged-test-v1") {
		t.Fatal("missing catalog entries should not be library-visible")
	}
}

func TestRegisterConflictingEntryPanics(t *testing.T) {
	entry := Entry{
		KeyType:      "catalog-conflict-v1",
		Family:       "catalog-conflict",
		Availability: AvailabilityDefaultEnabled,
	}
	unregisterForTest(t, entry.KeyType)
	Register(entry)

	defer func() {
		if recover() == nil {
			t.Fatal("Register() did not panic for conflicting entry")
		}
	}()
	entry.Availability = AvailabilityLibrary
	Register(entry)
}

// EntriesForTest, which the valid_rekey_target decision test iterates, returns
// entries of every availability, internal-only and disabled included.
func TestEntriesForTestReturnsEveryAvailability(t *testing.T) {
	want := map[string]Availability{
		"catalog-all-default-v1":  AvailabilityDefaultEnabled,
		"catalog-all-library-v1":  AvailabilityLibrary,
		"catalog-all-internal-v1": AvailabilityInternalOnly,
		"catalog-all-disabled-v1": AvailabilityDisabled,
	}
	for keyType, availability := range want {
		unregisterForTest(t, keyType)
		Register(Entry{KeyType: keyType, Family: keyType, Availability: availability})
	}
	found := map[string]Availability{}
	for _, entry := range EntriesForTest() {
		if _, ok := want[entry.KeyType]; ok {
			found[entry.KeyType] = entry.Availability
		}
	}
	for keyType, availability := range want {
		if found[keyType] != availability {
			t.Errorf("EntriesForTest() has %s as %q, want %q", keyType, found[keyType], availability)
		}
	}
}
