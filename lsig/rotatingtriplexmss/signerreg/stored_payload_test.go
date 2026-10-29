// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
)

// TestStoredPayloadStillLoads loads testdata/stored_payload.json, the
// decrypted key file payload this key type wrote for fixedPayload's seed and
// network before the rotating family refactor; its public_key is the packed
// stage 0 record. The fixture is never regenerated: a failure means existing
// key files no longer load, or new ones are no longer laid out as they were.
// Loading needs no tree; the comparison with a new payload builds tree 0.
func TestStoredPayloadStillLoads(t *testing.T) {
	Register()
	stored, err := os.ReadFile(filepath.Join("testdata", "stored_payload.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(stored)
	parsed, err := keys.ParsePayload(stored)
	if err != nil {
		t.Fatalf("stored payload no longer loads: %v", err)
	}
	defer parsed.ZeroSecrets()
	selector, err := parsed.Selector()
	if err != nil {
		t.Fatal(err)
	}
	if selector != goldenAddress {
		t.Fatalf("stored payload is account %s, want %s", selector, goldenAddress)
	}
	fresh, address := fixedPayload(t)
	if !bytes.Equal(parsed.PrivateKey, fresh.PrivateKey) || !bytes.Equal(parsed.GenesisHash, fresh.GenesisHash) {
		t.Fatal("fixture is not fixedPayload's seed and network")
	}
	if selector != address {
		t.Fatalf("stored payload is account %s, a new one for the same seed is %s", selector, address)
	}
	if !bytes.Equal(parsed.PublicKey, fresh.PublicKey) {
		t.Fatal("a new key file's stage 0 record is laid out differently from the stored one")
	}
}
