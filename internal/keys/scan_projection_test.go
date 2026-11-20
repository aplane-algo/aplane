// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"encoding/json"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// The scan projects the payload's non-secret fields into KeyScanInfo.
func TestScanProjectsPayloadFields(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := genstoretest.MintFirst(t, storepaths.NewPaths(t.TempDir()))
	keyJSON, address := testEd25519Key(t)
	var keyData map[string]interface{}
	if err := json.Unmarshal(keyJSON, &keyData); err != nil {
		t.Fatal(err)
	}
	keyData["created_at"] = "2026-01-15T10:30:00Z"
	keyData["valid_rekey_target"] = true
	keyJSON, _ = json.MarshalIndent(keyData, "", "  ")
	writeKeyFile(t, paths, address, keyJSON, masterKey)

	result, err := ScanKeysDirectoryWithKeyring(paths, cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatal(err)
	}
	info := result[address]
	if info.KeyType != keyData["key_type"] || info.Category != keyData["category"] ||
		info.PublicKeyHex != keyData["public_key"] || info.CreatedAt != "2026-01-15T10:30:00Z" ||
		!info.ValidRekeyTarget || info.TemplateFingerprint != "" {
		t.Fatalf("scan info = %+v", info)
	}
}
