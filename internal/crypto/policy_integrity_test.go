// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"bytes"
	"testing"
)

func TestDerivePolicyIntegrityKey(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0x42}, 32)
	key1, err := derivePolicyIntegrityKey(masterKey)
	if err != nil {
		t.Fatalf("derivePolicyIntegrityKey() error = %v", err)
	}
	defer ZeroBytes(key1)
	key2, err := derivePolicyIntegrityKey(masterKey)
	if err != nil {
		t.Fatalf("derivePolicyIntegrityKey() second error = %v", err)
	}
	defer ZeroBytes(key2)

	if len(key1) != PolicyIntegrityKeyLength {
		t.Fatalf("derived key length = %d, want %d", len(key1), PolicyIntegrityKeyLength)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatal("derivation is not deterministic")
	}

	otherKey, err := derivePolicyIntegrityKey(bytes.Repeat([]byte{0x43}, 32))
	if err != nil {
		t.Fatalf("derivePolicyIntegrityKey(other) error = %v", err)
	}
	defer ZeroBytes(otherKey)
	if bytes.Equal(key1, otherKey) {
		t.Fatal("different master keys derived the same policy integrity key")
	}
}

func TestDerivePolicyIntegrityKeyRejectsEmptyMasterKey(t *testing.T) {
	if _, err := derivePolicyIntegrityKey(nil); err == nil {
		t.Fatal("derivePolicyIntegrityKey(nil) error = nil, want failure")
	}
}
