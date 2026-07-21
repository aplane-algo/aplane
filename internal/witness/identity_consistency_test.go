// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package witness_test

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

func TestFalconSizesMatchFamily(t *testing.T) {
	publicSize, ok := witness.PublicKeySize(witness.Falcon1024V1)
	if !ok || publicSize != family.PublicKeySize {
		t.Fatalf("PublicKeySize() = %d, %v; want %d", publicSize, ok, family.PublicKeySize)
	}
	privateSize, ok := witness.PrivateKeySize(witness.Falcon1024V1)
	if !ok || privateSize != family.PrivateKeySize {
		t.Fatalf("PrivateKeySize() = %d, %v; want %d", privateSize, ok, family.PrivateKeySize)
	}
	if witness.Falcon1024SignatureSize != family.MaxSignatureSize {
		t.Fatalf("Falcon1024SignatureSize = %d, want %d", witness.Falcon1024SignatureSize, family.MaxSignatureSize)
	}
}
