// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package recovered

import (
	"bytes"
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
	masterKey := bytes.Repeat([]byte{0x42}, 32)
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
	if meta.Selector != address || meta.EntryFile != EntryFileName(address) || !sha256Shape.MatchString(meta.EntrySHA256) {
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
	if entry.RestoreID != batch.RestoreID {
		t.Fatalf("LoadEntry().RestoreID = %q, want %q", entry.RestoreID, batch.RestoreID)
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
	masterKey := bytes.Repeat([]byte{0x24}, 32)
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
	masterKey := bytes.Repeat([]byte{0x35}, 32)
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

func TestLoadRecoveredEntryRejectsCrossBatchSubstitution(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	masterKey := bytes.Repeat([]byte{0x46}, 32)
	address, keyJSON := keystest.Ed25519KeyJSON(t)
	payload, err := keys.ParsePayload(keyJSON)
	if err != nil {
		t.Fatalf("ParsePayload() error = %v", err)
	}
	defer payload.ZeroSecrets()
	payload.CreatedAt = payload.CreatedAt.Add(time.Second)
	alternateKeyJSON, err := keys.MarshalPayload(payload)
	if err != nil {
		t.Fatalf("MarshalPayload() error = %v", err)
	}
	defer func() {
		for i := range alternateKeyJSON {
			alternateKeyJSON[i] = 0
		}
	}()
	archiveSum := sha256.Sum256([]byte("archive"))
	create := func(key []byte) *Batch {
		t.Helper()
		batch, createErr := Create(paths, "default", CreateRequest{
			ArchiveName:        "backup.tar.gz",
			ArchiveSHA256:      hex.EncodeToString(archiveSum[:]),
			SourceNodeRole:     "signer",
			SourcePolicyStatus: SourcePolicyMissing,
			Entries: []Entry{{
				Selector: address,
				Category: keys.CategoryEd25519,
				KeyType:  "ed25519",
				KeyJSON:  key,
			}},
		}, masterKey)
		if createErr != nil {
			t.Fatalf("Create() error = %v", createErr)
		}
		return batch
	}
	first := create(keyJSON)
	second := create(alternateKeyJSON)
	firstMeta := first.Entries[0]
	secondEntryPath := filepath.Join(paths.RecoveredBatchEntriesDir("default", second.RestoreID), second.Entries[0].EntryFile)
	substitute, err := os.ReadFile(secondEntryPath)
	if err != nil {
		t.Fatalf("ReadFile(second entry) error = %v", err)
	}
	firstEntryPath := filepath.Join(paths.RecoveredBatchEntriesDir("default", first.RestoreID), firstMeta.EntryFile)
	if err := os.WriteFile(firstEntryPath, substitute, fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(substitute) error = %v", err)
	}
	if _, err := LoadEntry(paths, "default", first.RestoreID, firstMeta, masterKey); err == nil ||
		!strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("LoadEntry(substituted) error = %v, want digest mismatch", err)
	}
}

func TestLoadRecoveredBatchRejectsSymlink(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	masterKey := bytes.Repeat([]byte{0x57}, 32)
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
	batchPath := paths.RecoveredBatchMetadataPath("default", batch.RestoreID)
	realPath := batchPath + ".real"
	if err := os.Rename(batchPath, realPath); err != nil {
		t.Fatalf("Rename(batch) error = %v", err)
	}
	if err := os.Symlink(realPath, batchPath); err != nil {
		t.Fatalf("Symlink(batch) error = %v", err)
	}
	if _, err := LoadBatch(paths, "default", batch.RestoreID, masterKey); err == nil {
		t.Fatal("LoadBatch(symlink) error = nil, want rejection")
	}
}

func TestCreateRejectsInvalidArchiveNamesAndTemplateTypes(t *testing.T) {
	address, keyJSON := keystest.Ed25519KeyJSON(t)
	archiveSum := sha256.Sum256([]byte("archive"))
	baseRequest := CreateRequest{
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
	}
	for _, name := range []string{".", "..", "dir/name", `dir\name`, strings.Repeat("a", maxArchiveNameBytes+1)} {
		t.Run("archive_"+strings.ReplaceAll(name, "/", "_"), func(t *testing.T) {
			paths := storepaths.NewPaths(t.TempDir())
			req := baseRequest
			req.ArchiveName = name
			if _, err := Create(paths, "default", req, bytes.Repeat([]byte{0x68}, 32)); err == nil {
				t.Fatalf("Create(archive_name=%q) error = nil", name)
			}
		})
	}

	paths := storepaths.NewPaths(t.TempDir())
	req := baseRequest
	req.Entries = append([]Entry(nil), baseRequest.Entries...)
	req.Entries[0].TemplateYAML = []byte("schema_version: 1\n")
	req.Entries[0].TemplateType = "unsupported"
	if _, err := Create(paths, "default", req, bytes.Repeat([]byte{0x79}, 32)); err == nil ||
		!strings.Contains(err.Error(), "unsupported recovered entry template_type") {
		t.Fatalf("Create(unsupported template type) error = %v", err)
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
