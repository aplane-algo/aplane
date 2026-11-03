// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"bytes"
	"context"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/keys"
	nativereg "github.com/aplane-algo/aplane/internal/signing/falcon1024/signerreg"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestNativeFalconBackupPreservesRecoveryEntropy(t *testing.T) {
	nativereg.RegisterSigner()
	source := mintFirstGenerationForBackupTest(t, storepaths.NewPaths(t.TempDir()))
	kr := cryptotest.Keyring(t, testExportMasterKey)
	entropy := make([]byte, 32)
	defer crypto.ZeroBytes(entropy)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	generated, err := (&keygen.NativeFalconGenerator{}).GenerateFromSeed(context.Background(), source, entropy, kr, "falcon1024", nil)
	if err != nil {
		t.Fatal(err)
	}
	exported := t.TempDir()
	if _, _, err := ExportKey(source, activePathsForBackupTest(t, source).KeysDir(), exported, generated.Address, kr, []byte("export-passphrase")); err != nil {
		t.Fatal(err)
	}
	dest := mintFirstGenerationForBackupTest(t, storepaths.NewPaths(t.TempDir()))
	active := activePathsForBackupTest(t, dest)
	_, err = NewRestorer(dest).WithActiveNamespace(active).RestoreKey(exported, generated.Address, kr, []byte("export-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := keys.ReadDecryptedKeyJSONWithKeyring(keys.AccountKeyFilePathActive(active, generated.Address), kr)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(raw)
	payload, err := keys.ParsePayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer payload.ZeroSecrets()
	if payload.FormatVersion != keys.NativeRecoveryKeyFormatVersion || !bytes.Equal(payload.RecoveryEntropy, entropy) {
		t.Fatal("backup/restore lost recovery entropy")
	}
}
