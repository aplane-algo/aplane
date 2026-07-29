// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package recovered

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
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
	}, cryptotest.Keyring(t, masterKey))
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

	loaded, err := LoadBatch(paths, "default", batch.RestoreID, cryptotest.Keyring(t, masterKey))
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
	entry, err := LoadEntry(paths, "default", batch.RestoreID, meta, cryptotest.Keyring(t, masterKey))
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
	}, cryptotest.Keyring(t, masterKey))
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
	}, cryptotest.Keyring(t, masterKey))
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
	if _, err := LoadBatch(paths, "default", batch.RestoreID, cryptotest.Keyring(t, masterKey)); err == nil {
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
		}, cryptotest.Keyring(t, masterKey))
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
	// The entry's restore ID is bound into the envelope's authenticated data,
	// so an entry lifted from another batch fails to open at all. The digest
	// check behind it stays as defence in depth for a same-batch swap.
	if _, err := LoadEntry(paths, "default", first.RestoreID, firstMeta, cryptotest.Keyring(t, masterKey)); err == nil ||
		!strings.Contains(err.Error(), "failed to decrypt recovered-entry:"+first.RestoreID) {
		t.Fatalf("LoadEntry(substituted) error = %v, want an authentication failure", err)
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
	}, cryptotest.Keyring(t, masterKey))
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
	if _, err := LoadBatch(paths, "default", batch.RestoreID, cryptotest.Keyring(t, masterKey)); err == nil {
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
			if _, err := Create(paths, "default", req, cryptotest.Keyring(t, bytes.Repeat([]byte{0x68}, 32))); err == nil {
				t.Fatalf("Create(archive_name=%q) error = nil", name)
			}
		})
	}

	paths := storepaths.NewPaths(t.TempDir())
	req := baseRequest
	req.Entries = append([]Entry(nil), baseRequest.Entries...)
	req.Entries[0].TemplateYAML = []byte("schema_version: 1\n")
	req.Entries[0].TemplateType = "unsupported"
	if _, err := Create(paths, "default", req, cryptotest.Keyring(t, bytes.Repeat([]byte{0x79}, 32))); err == nil ||
		!strings.Contains(err.Error(), "unsupported recovered entry template_type") {
		t.Fatalf("Create(unsupported template type) error = %v", err)
	}
}

func TestValidateBatchRejectsInvalidPolicyAndEntryOrdering(t *testing.T) {
	firstAddress, firstKeyJSON := keystest.Ed25519KeyJSON(t)
	defer crypto.ZeroBytes(firstKeyJSON)
	secondAddress, secondKeyJSON := keystest.Ed25519KeyJSON(t)
	defer crypto.ZeroBytes(secondKeyJSON)
	if firstAddress > secondAddress {
		firstAddress, secondAddress = secondAddress, firstAddress
	}
	valid := func() Batch {
		return Batch{
			Schema:             BatchSchema,
			RestoreID:          "0123456789abcdef0123456789abcdef",
			CreatedAt:          time.Unix(1234, 0).UTC(),
			ArchiveName:        "backup.tar.gz",
			ArchiveSHA256:      strings.Repeat("a", 64),
			SourceNodeRole:     "signer",
			SourcePolicyStatus: SourcePolicyMissing,
			Entries: []BatchEntry{
				{
					Selector:    firstAddress,
					Category:    keys.CategoryEd25519,
					KeyType:     "ed25519",
					EntryFile:   EntryFileName(firstAddress),
					EntrySHA256: strings.Repeat("b", 64),
				},
				{
					Selector:    secondAddress,
					Category:    keys.CategoryEd25519,
					KeyType:     "ed25519",
					EntryFile:   EntryFileName(secondAddress),
					EntrySHA256: strings.Repeat("c", 64),
				},
			},
		}
	}
	emptyPolicySum := sha256.Sum256(nil)
	emptyPolicyBatch := valid()
	emptyPolicyBatch.SourcePolicyStatus = SourcePolicyUnverified
	emptyPolicyBatch.SourcePolicySHA256 = hex.EncodeToString(emptyPolicySum[:])
	if err := validateBatch(&emptyPolicyBatch); err != nil {
		t.Fatalf("validateBatch(empty present policy) error = %v", err)
	}
	autoApprove := false
	sourceSettingsBatch := valid()
	sourceSettingsBatch.SourceUserAutoApprove = &autoApprove
	if err := validateBatch(&sourceSettingsBatch); err != nil {
		t.Fatalf("validateBatch(valid source settings) error = %v", err)
	}
	tests := []struct {
		name    string
		mutate  func(*Batch)
		wantErr string
	}{
		{
			name: "missing status carries policy data",
			mutate: func(batch *Batch) {
				batch.SourcePolicyYAML = []byte("reject_foreign_rekey: true\n")
			},
			wantErr: "missing source policy must not include policy data",
		},
		{
			name: "policy digest mismatch",
			mutate: func(batch *Batch) {
				batch.SourcePolicyStatus = SourcePolicyUnverified
				batch.SourcePolicyYAML = []byte("reject_foreign_rekey: true\n")
				batch.SourcePolicySHA256 = strings.Repeat("0", 64)
			},
			wantErr: "source policy digest mismatch",
		},
		{
			name: "unsorted entries",
			mutate: func(batch *Batch) {
				batch.Entries[0], batch.Entries[1] = batch.Entries[1], batch.Entries[0]
			},
			wantErr: "entries are not sorted",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			batch := valid()
			test.mutate(&batch)
			if err := validateBatch(&batch); err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateBatch() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestLegacyBatchViewIgnoresAdditiveSourceSettings(t *testing.T) {
	autoApprove := false
	batch := Batch{
		Schema:                    BatchSchema,
		RestoreID:                 "0123456789abcdef0123456789abcdef",
		CreatedAt:                 time.Unix(1234, 0).UTC(),
		ArchiveName:               "backup.tar.gz",
		ArchiveSHA256:             strings.Repeat("a", 64),
		SourceNodeRole:            "signer",
		SourcePolicyStatus:        SourcePolicyMissing,
		SourceUserAutoApprove:     &autoApprove,
		SourceGenesisHashMappings: nil,
		Entries: []BatchEntry{{
			Selector:    "selector",
			Category:    "category",
			KeyType:     "key-type",
			EntryFile:   "entry.recovered",
			EntrySHA256: strings.Repeat("c", 64),
		}},
	}
	plaintext, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("Marshal(batch) error = %v", err)
	}
	defer crypto.ZeroBytes(plaintext)

	type legacyBatchView struct {
		Schema             string             `json:"schema"`
		RestoreID          string             `json:"restore_id"`
		SourcePolicyStatus SourcePolicyStatus `json:"source_policy_status"`
		Entries            []BatchEntry       `json:"entries"`
	}
	var legacy legacyBatchView
	if err := json.Unmarshal(plaintext, &legacy); err != nil {
		t.Fatalf("legacy Unmarshal(new v1 batch) error = %v", err)
	}
	if legacy.Schema != BatchSchema ||
		legacy.RestoreID != batch.RestoreID ||
		legacy.SourcePolicyStatus != SourcePolicyMissing ||
		len(legacy.Entries) != 1 {
		t.Fatalf("legacy batch view = %+v, want core v1 fields preserved", legacy)
	}
}

func TestLoadBatchRejectsRestoreIDMismatch(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	masterKey := bytes.Repeat([]byte{0x7a}, 32)
	batch := createRotationTestBatch(t, paths, masterKey)
	path := paths.RecoveredBatchMetadataPath("default", batch.RestoreID)
	encrypted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(batch) error = %v", err)
	}
	plaintext, err := crypto.DecryptWithTermKey(
		encrypted, masterKey, crypto.FirstTerm, crypto.RecoveredBatchContext(batch.RestoreID),
	)
	if err != nil {
		t.Fatalf("DecryptWithTermKey(batch) error = %v", err)
	}
	defer crypto.ZeroBytes(plaintext)
	var stored Batch
	if err := json.Unmarshal(plaintext, &stored); err != nil {
		t.Fatalf("Unmarshal(batch) error = %v", err)
	}
	stored.RestoreID = "abcdef0123456789abcdef0123456789"
	reencoded, err := json.Marshal(&stored)
	if err != nil {
		t.Fatalf("Marshal(batch) error = %v", err)
	}
	defer crypto.ZeroBytes(reencoded)
	// Sealed under the batch's on-disk identity, so the payload's edited
	// restore ID is what the load path has to catch.
	reEncrypted, err := crypto.EncryptWithTermKey(
		reencoded, masterKey, crypto.FirstTerm, crypto.RecoveredBatchContext(batch.RestoreID),
	)
	if err != nil {
		t.Fatalf("EncryptWithTermKey(batch) error = %v", err)
	}
	if err := os.WriteFile(path, reEncrypted, fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(batch) error = %v", err)
	}

	if _, err := LoadBatch(paths, "default", batch.RestoreID, cryptotest.Keyring(t, masterKey)); err == nil ||
		!strings.Contains(err.Error(), "restore ID mismatch") {
		t.Fatalf("LoadBatch() error = %v, want restore ID mismatch", err)
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
