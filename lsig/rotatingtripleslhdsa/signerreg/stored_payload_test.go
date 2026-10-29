// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
)

// TestStoredPayloadStillLoads loads testdata/stored_payload_h<height>.json,
// the decrypted key file payload this key type wrote for fixedPayload's seed
// and network before the rotating family refactor; its public_key is the
// packed stage 0 record, whose root follows from the hypertree height the
// binary is built with. The fixture is never regenerated: a failure means
// existing key files no longer load, or new ones are no longer laid out as
// they were.
func TestStoredPayloadStillLoads(t *testing.T) {
	Register()
	name := fmt.Sprintf("stored_payload_h%d.json", rotatingkey.RotatingSlhdsaHeight)
	stored, err := os.ReadFile(filepath.Join("testdata", name))
	if errors.Is(err, fs.ErrNotExist) {
		t.Skipf("no stored payload fixture for hypertree height %d", rotatingkey.RotatingSlhdsaHeight)
	}
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
