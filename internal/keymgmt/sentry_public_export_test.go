// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keymgmt

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

func TestNewSentryPublicKeyExportEd25519(t *testing.T) {
	pub := bytesOfLen(32, 0xab)
	componentKey, err := keytypes.ComponentKeySelector(keytypes.SentryComponentEd25519V1, pub)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}

	env, err := NewSentryPublicKeyExport(componentKey, keytypes.SentryComponentEd25519V1, strings.ToUpper(hex.EncodeToString(pub)))
	if err != nil {
		t.Fatalf("NewSentryPublicKeyExport() error = %v", err)
	}
	sum := sha256.Sum256(pub)
	if env.Schema != SentryPublicKeyExportSchema {
		t.Fatalf("Schema = %q, want %q", env.Schema, SentryPublicKeyExportSchema)
	}
	if env.ComponentKey != componentKey {
		t.Fatalf("ComponentKey = %q, want %q", env.ComponentKey, componentKey)
	}
	if env.KeyType != keytypes.SentryComponentEd25519V1 {
		t.Fatalf("KeyType = %q, want %q", env.KeyType, keytypes.SentryComponentEd25519V1)
	}
	if env.PublicKeyEncoding != "hex" {
		t.Fatalf("PublicKeyEncoding = %q, want hex", env.PublicKeyEncoding)
	}
	if env.PublicKeyHex != hex.EncodeToString(pub) {
		t.Fatalf("PublicKeyHex = %q, want normalized lowercase hex", env.PublicKeyHex)
	}
	if env.PublicKeySize != len(pub) {
		t.Fatalf("PublicKeySize = %d, want %d", env.PublicKeySize, len(pub))
	}
	if env.PublicKeySHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("PublicKeySHA256 = %q, want %q", env.PublicKeySHA256, hex.EncodeToString(sum[:]))
	}
}

func TestNewSentryPublicKeyExportFalcon1024(t *testing.T) {
	pub := bytesOfLen(falconfamily.PublicKeySize, 0xcd)
	componentKey, err := keytypes.ComponentKeySelector(keytypes.SentryComponentFalcon1024V1, pub)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}

	env, err := NewSentryPublicKeyExport(componentKey, keytypes.SentryComponentFalcon1024V1, hex.EncodeToString(pub))
	if err != nil {
		t.Fatalf("NewSentryPublicKeyExport() error = %v", err)
	}
	if env.PublicKeySize != falconfamily.PublicKeySize {
		t.Fatalf("PublicKeySize = %d, want %d", env.PublicKeySize, falconfamily.PublicKeySize)
	}
	if env.ComponentKey != componentKey {
		t.Fatalf("ComponentKey = %q, want %q", env.ComponentKey, componentKey)
	}
}

func TestNewSentryPublicKeyExportRejectsMismatchedSelector(t *testing.T) {
	pub := bytesOfLen(32, 0xab)
	otherPub := bytesOfLen(32, 0xbc)
	componentKey, err := keytypes.ComponentKeySelector(keytypes.SentryComponentEd25519V1, otherPub)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}

	_, err = NewSentryPublicKeyExport(componentKey, keytypes.SentryComponentEd25519V1, hex.EncodeToString(pub))
	if err == nil {
		t.Fatal("NewSentryPublicKeyExport() error = nil, want selector mismatch")
	}
	if !strings.Contains(err.Error(), "does not match public key-derived selector") {
		t.Fatalf("NewSentryPublicKeyExport() error = %v, want selector mismatch", err)
	}
}

func TestNewSentryPublicKeyExportRejectsSpendingKeyType(t *testing.T) {
	pub := bytesOfLen(32, 0xab)
	componentKey, err := keytypes.ComponentKeySelector(keytypes.SentryComponentEd25519V1, pub)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}

	_, err = NewSentryPublicKeyExport(componentKey, "ed25519", hex.EncodeToString(pub))
	if err == nil {
		t.Fatal("NewSentryPublicKeyExport() error = nil, want non-component key type rejection")
	}
	if !strings.Contains(err.Error(), "is not a sentry component key type") {
		t.Fatalf("NewSentryPublicKeyExport() error = %v, want non-component key type rejection", err)
	}
}

func bytesOfLen(n int, fill byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = fill
	}
	return b
}
