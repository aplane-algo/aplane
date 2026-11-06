// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package v1

import (
	"bytes"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/aplane-algo/aplane/internal/sigconstruction"
	"github.com/aplane-algo/aplane/lsig/ed25519lsig/family"
)

// Ed25519 has no program golden, so the footer is pinned here.
func TestBuildVerifyTEALIsByteExact(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, family.PublicKeySize)
	got, err := NewOps().BuildVerifyTEAL(key)
	if err != nil {
		t.Fatal(err)
	}
	want := "// === Ed25519 Signature Verification ===\ntxn TxID\narg 0\npushbytes 0x" + hex.EncodeToString(key) + "\ned25519verify_bare\n"
	if got != want {
		t.Fatalf("BuildVerifyTEAL() = %q", got)
	}
	if _, err := NewOps().BuildVerifyTEAL(key[1:]); err == nil {
		t.Fatal("BuildVerifyTEAL() accepted a short key")
	}
}

func TestCatalogMatchesFamilySizes(t *testing.T) {
	construction := sigconstruction.Ed25519()
	if got := construction.PublicKeySize(); got != family.PublicKeySize {
		t.Fatalf("PublicKeySize() = %d", got)
	}
	layout := NewOps().SignatureArgLayout()
	if layout.Count != 1 || !slices.Equal(layout.MaxSizes, []int{family.MaxSignatureSize}) {
		t.Fatalf("SignatureArgLayout() = %+v", layout)
	}
	signature := make([]byte, family.MaxSignatureSize)
	if args, err := NewOps().BuildSignatureArgs(signature); err != nil || len(args) != 1 {
		t.Fatalf("BuildSignatureArgs() = %d args, %v", len(args), err)
	}
	if _, err := NewOps().BuildSignatureArgs(signature[1:]); err == nil {
		t.Fatal("BuildSignatureArgs() accepted a short signature")
	}
}
