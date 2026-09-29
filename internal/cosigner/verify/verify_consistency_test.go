// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package verify

import (
	"testing"

	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

// TestFalconSizesMatchFamily pins the literal Falcon-1024 sizes declared in
// this package (kept local so production code has no lsig family imports) to
// the authoritative constants in lsig/falcon1024/family.
func TestFalconSizesMatchFamily(t *testing.T) {
	if falcon1024PublicKeySize != family.PublicKeySize {
		t.Fatalf("falcon1024PublicKeySize = %d, want %d", falcon1024PublicKeySize, family.PublicKeySize)
	}
	if falcon1024MaxSignatureSize != family.MaxSignatureSize {
		t.Fatalf("falcon1024MaxSignatureSize = %d, want %d", falcon1024MaxSignatureSize, family.MaxSignatureSize)
	}
}
