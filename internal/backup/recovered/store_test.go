// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package recovered

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestCreateAndLoadRecoveredBatch(t *testing.T) {
	root := t.TempDir()
	paths := storepaths.NewPaths(root)
	masterKey := bytesOf(0x42, 32)
	address, keyJSON := keystest.Ed25519KeyJSON(t)
	policyYAML := []byte("reject_foreign_rekey: true\n")
	policySum := sha256.Sum256(policyYAML)
	archiveSum := sha256.Sum256([]byte("archive"))

	batch, err := Create(paths, "default", CreateRequest{
		ArchiveName:        "backup.tar.gz",
		ArchiveSHA256:      hex.EncodeToString(archiveSum[:]),
		SourceNodeRole:     "signer",
		SourcePolicyStatus: SourcePolicyUnverified,
		SourcePolicySHA256: hex.EncodeToString(policySum[:]),
		SourcePolicyYAML:   policyYAML,
		CreatedAt:          time.Unix(1234, 0),
		Entries: []Entry{{
			Selector: address,
			Category: keys.CategoryEd25519,
			KeyType:  "ed25519",
			KeyJSON:  keyJSON,
		}},
	}, masterKey)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := ValidateRestoreID(batch.RestoreID); err != nil {
		t.Fatalf("ValidateRestoreID() error = %v", err)
	}

	batchDir := paths.RecoveredBatchDir("default", batch.RestoreID)
	assertMode(t, batchDir, fsutil.StoreDirPerm)
	assertMode(t, paths.RecoveredBatchEntriesDir("default", batch.RestoreID), fsutil.StoreDirPerm)
	assertMode(t, paths.RecoveredBatchMetadataPath("default", batch.RestoreID), fsutil.StoreFilePerm)

	loaded, err := LoadBatch(paths, "default", batch.RestoreID, masterKey)
	if err != nil {
		t.Fatalf("LoadBatch() error = %v", err)
	}
	if loaded.ArchiveSHA256 != batch.ArchiveSHA256 || len(loaded.Entries) != 1 {
		t.Fatalf("LoadBatch() = %+v", loaded)
	}
	meta := loaded.Entries[0]
	if meta.Selector != address || meta.EntryFile != EntryFileName(address) {
		t.Fatalf("loaded entry metadata = %+v", meta)
	}

	entryPath := filepath.Join(paths.RecoveredBatchEntriesDir("default", batch.RestoreID), meta.EntryFile)
	assertMode(t, entryPath, fsutil.StoreFilePerm)
	entry, err := LoadEntry(paths, "default", batch.RestoreID, meta, masterKey)
	if err != nil {
		t.Fatalf("LoadEntry() error = %v", err)
	}
	defer entry.ZeroSecrets()
	if entry.Selector != address || entry.KeyType != "ed25519" {
		t.Fatalf("LoadEntry() = %+v", entry)
	}
	if _, err := os.Stat(paths.KeysDir("default")); !os.IsNotExist(err) {
		t.Fatalf("active keys directory exists after recovered batch creation: %v", err)
	}
	if _, err := os.Stat(paths.KeyTypeRecordsDir("default")); !os.IsNotExist(err) {
		t.Fatalf("active key type records directory exists after recovered batch creation: %v", err)
	}
}

func TestCreateRecoveredBatchIsAllOrNothing(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	masterKey := bytesOf(0x24, 32)
	address, keyJSON := keystest.Ed25519KeyJSON(t)
	archiveSum := sha256.Sum256([]byte("archive"))

	_, err := Create(paths, "default", CreateRequest{
		ArchiveName:        "backup.tar.gz",
		ArchiveSHA256:      hex.EncodeToString(archiveSum[:]),
		SourceNodeRole:     "signer",
		SourcePolicyStatus: SourcePolicyMissing,
		Entries: []Entry{
			{
				Selector: address,
				Category: keys.CategoryEd25519,
				KeyType:  "ed25519",
				KeyJSON:  keyJSON,
			},
			{
				Selector: "not-an-address",
				Category: keys.CategoryEd25519,
				KeyType:  "ed25519",
				KeyJSON:  keyJSON,
			},
		},
	}, masterKey)
	if err == nil {
		t.Fatal("Create() error = nil, want invalid entry")
	}
	entries, readErr := os.ReadDir(paths.RecoveredRootDir("default"))
	if readErr != nil && !os.IsNotExist(readErr) {
		t.Fatalf("ReadDir(recovered) error = %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("recovered root entries = %v, want empty", entries)
	}
}

func TestLoadRecoveredBatchRejectsTampering(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	masterKey := bytesOf(0x35, 32)
	address, keyJSON := keystest.Ed25519KeyJSON(t)
	archiveSum := sha256.Sum256([]byte("archive"))
	batch, err := Create(paths, "default", CreateRequest{
		ArchiveName:        "backup.tar.gz",
		ArchiveSHA256:      hex.EncodeToString(archiveSum[:]),
		SourceNodeRole:     "signer",
		SourcePolicyStatus: SourcePolicyMissing,
		Entries: []Entry{{
			Selector: address,
			Category: keys.CategoryEd25519,
			KeyType:  "ed25519",
			KeyJSON:  keyJSON,
		}},
	}, masterKey)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	path := paths.RecoveredBatchMetadataPath("default", batch.RestoreID)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(batch) error = %v", err)
	}
	index := strings.Index(string(data), `"ciphertext": "`)
	if index < 0 {
		t.Fatalf("encrypted batch has no ciphertext: %s", data)
	}
	index += len(`"ciphertext": "`)
	if data[index] == 'A' {
		data[index] = 'B'
	} else {
		data[index] = 'A'
	}
	if err := os.WriteFile(path, data, fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(tampered batch) error = %v", err)
	}
	if _, err := LoadBatch(paths, "default", batch.RestoreID, masterKey); err == nil {
		t.Fatal("LoadBatch() error = nil, want tamper rejection")
	}
}

func TestValidateRestoreID(t *testing.T) {
	valid := "0123456789abcdef0123456789abcdef"
	if err := ValidateRestoreID(valid); err != nil {
		t.Fatalf("ValidateRestoreID(%q) error = %v", valid, err)
	}
	for _, invalid := range []string{"", "abc", strings.ToUpper(valid), "../" + valid, valid + "00"} {
		if err := ValidateRestoreID(invalid); err == nil {
			t.Errorf("ValidateRestoreID(%q) error = nil", invalid)
		}
	}
}

func bytesOf(value byte, count int) []byte {
	out := make([]byte, count)
	for i := range out {
		out[i] = value
	}
	return out
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s) error = %v", path, err)
	}
	if got := info.Mode().Perm(); got != want.Perm() {
		t.Fatalf("%s mode = %04o, want %04o", path, got, want.Perm())
	}
}
