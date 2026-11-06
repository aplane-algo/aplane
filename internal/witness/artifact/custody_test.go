// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package artifact_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness/artifact"
)

// Sharing .cos must not allow either custody reader to accept the other
// encryption format, even when the filename carries the correct key ID.
func TestCosignerFilesRequireTheirCustodyEncryptionFormat(t *testing.T) {
	files, err := artifact.GenerateFiles(t.TempDir(), []byte("standalone passphrase"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	standalone, err := artifact.LoadFile(files.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	paths := genstoretest.MintFirst(t, storepaths.NewPaths(t.TempDir()))
	active := genstoretest.Active(t, paths)
	storePath := keys.CosignerCredentialFilePathActive(active, files.Reference.WitnessKeyID)
	if err := os.WriteFile(storePath, standalone, 0o600); err != nil {
		t.Fatal(err)
	}
	keyring, err := crypto.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer keyring.Zero()
	report, err := keys.ScanKeysDirectoryWithKeyringReportActive(active, keyring)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Keys) != 0 || len(report.Warnings) != 1 || report.Warnings[0].Code != keys.KeyScanWarningReadFailed {
		t.Fatalf("standalone .cos accepted by store reader: keys=%d warnings=%v", len(report.Keys), report.Warnings)
	}

	// Conversely, an otherwise valid store term envelope cannot be interpreted
	// as a standalone passphrase-encrypted bundle by aprekey.
	storeEncrypted, err := keyring.Seal([]byte("store payload"), crypto.CosignerCredentialContext(files.Reference.WitnessKeyID))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), files.Reference.WitnessKeyID+".cos")
	if err := os.WriteFile(path, storeEncrypted, 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := artifact.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := artifact.Inspect(data); err == nil {
		t.Fatal("standalone reader accepted store-encrypted .cos")
	}
	if _, err := artifact.Verify(data, []byte("standalone passphrase")); err == nil {
		t.Fatal("standalone verification accepted store-encrypted .cos")
	}
}
