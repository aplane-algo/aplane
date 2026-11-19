// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package algorithm

import "testing"

// TestGetMetadataResolvesOnlyRegisteredIdentities pins that GetMetadata never
// guesses a family from the key-type string. Families register under
// qualified names, so a key type that merely contains one (an unregistered
// template from this or any other publisher) gets no metadata and the caller
// applies its own default.
func TestGetMetadataResolvesOnlyRegisteredIdentities(t *testing.T) {
	native := &basicMetadata{
		family:            "review.native",
		authorizationKind: AuthorizationNativePQ,
	}
	logicSig := &basicMetadata{
		family:            "review.logic",
		authorizationKind: AuthorizationLogicSig,
	}
	RegisterMetadata(native)
	RegisterMetadata(logicSig)

	if got, err := GetMetadata(native.family); err != nil || got != native {
		t.Fatalf("exact native metadata = %#v, %v; want registered metadata", got, err)
	}
	if got, err := GetMetadata(logicSig.family); err != nil || got != logicSig {
		t.Fatalf("exact LogicSig metadata = %#v, %v; want registered metadata", got, err)
	}
	for _, keyType := range []string{
		"review.native-policy.v1",
		"review.logic-policy.v1",
		"vendor.logic-policy.v1",
		"vendor.review.logic-policy.v1",
	} {
		if got, err := GetMetadata(keyType); err == nil {
			t.Errorf("GetMetadata(%q) = %#v, want unresolved", keyType, got)
		}
	}
}
