// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package algorithm

import "testing"

func TestGetMetadataPrefixFallbackIsLogicSigOnly(t *testing.T) {
	native := &basicMetadata{
		family:            "reviewnative",
		authorizationKind: AuthorizationNativePQ,
	}
	logicSig := &basicMetadata{
		family:            "reviewlogic",
		authorizationKind: AuthorizationLogicSig,
		requiresLogicSig:  true,
	}
	RegisterMetadata(native)
	RegisterMetadata(logicSig)

	if got, err := GetMetadata(native.family); err != nil || got != native {
		t.Fatalf("exact native metadata = %#v, %v; want registered metadata", got, err)
	}
	if got, err := GetMetadata("vendor.reviewnative-policy.v1"); err == nil {
		t.Fatalf("third-party native-prefix metadata = %#v, want unresolved", got)
	}
	if got, err := GetMetadata("vendor.reviewlogic-policy.v1"); err != nil || got != logicSig {
		t.Fatalf("LogicSig prefix metadata = %#v, %v; want registered base metadata", got, err)
	}
}
