// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package ecdsak1_test

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/mnemonic"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/ecdsak1"
	"github.com/aplane-algo/aplane/lsig/ecdsak1/signerreg"
)

func TestRegisterSigner(t *testing.T) {
	signerreg.RegisterSigner()

	if dsa := logicsigdsa.Get(ecdsak1.KeyTypeV1); dsa == nil {
		t.Fatalf("%s not registered in logicsigdsa", ecdsak1.KeyTypeV1)
	}

	if provider := signing.GetProvider(ecdsak1.KeyTypeV1); provider == nil {
		t.Fatalf("ecdsak1 signing provider not registered for %s", ecdsak1.KeyTypeV1)
	}

	if _, err := keygen.GetGenerator(ecdsak1.KeyTypeV1); err != nil {
		t.Fatalf("ecdsak1 keygen not registered: %v", err)
	}

	if _, err := mnemonic.GetHandler(ecdsak1.KeyTypeV1); err != nil {
		t.Fatalf("ecdsak1 mnemonic handler not registered: %v", err)
	}

	meta, err := algorithm.GetMetadata(ecdsak1.KeyTypeV1)
	if err != nil {
		t.Fatalf("ecdsak1 metadata not registered: %v", err)
	}
	if !meta.RequiresLogicSig() {
		t.Fatal("ecdsak1 metadata should require LogicSig")
	}
	if meta.Family() != ecdsak1.FamilyName {
		t.Fatalf("metadata.Family() = %q, want %q", meta.Family(), ecdsak1.FamilyName)
	}
}
