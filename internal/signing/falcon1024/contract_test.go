// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package falcon1024

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type keyVector struct {
	Source              string `json:"source"`
	EntropyHex          string `json:"entropy_hex"`
	MnemonicWordCount   int    `json:"mnemonic_word_count"`
	MnemonicSHA512256   string `json:"mnemonic_sha512_256"`
	WorkingSeedHex      string `json:"working_seed_hex"`
	PublicKeySHA512256  string `json:"public_key_sha512_256"`
	PrivateKeySHA512256 string `json:"private_key_sha512_256"`
	Salt                byte   `json:"salt"`
	Address             string `json:"address"`
}

func loadKeyVector(t *testing.T) keyVector {
	t.Helper()
	data, err := os.ReadFile("testdata/key_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector keyVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func TestNativeFalconContractVectorShape(t *testing.T) {
	vector := loadKeyVector(t)
	for name, value := range map[string]string{
		"entropy":            vector.EntropyHex,
		"working seed":       vector.WorkingSeedHex,
		"mnemonic digest":    vector.MnemonicSHA512256,
		"public key digest":  vector.PublicKeySHA512256,
		"private key digest": vector.PrivateKeySHA512256,
	} {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 32 {
			t.Fatalf("%s = %q, want canonical 32-byte hex", name, value)
		}
	}
	if vector.MnemonicWordCount != 25 {
		t.Fatalf("mnemonic word count = %d, want 25", vector.MnemonicWordCount)
	}
	if len(vector.Address) != 58 {
		t.Fatalf("address length = %d, want 58", len(vector.Address))
	}
	if !strings.Contains(vector.Source, "68e036affd9e62d0a64dcdb3f252eb0ee2e052d3") {
		t.Fatalf("fixture source is not pinned: %q", vector.Source)
	}
}
