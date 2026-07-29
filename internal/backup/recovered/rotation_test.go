// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package recovered

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestRotationTargetsSkipsStagingDirectories(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	stageDir := filepath.Join(paths.RecoveredRootDir("default"), StagingDirPrefix+"interrupted")
	if err := os.MkdirAll(filepath.Join(stageDir, "unexpected"), fsutil.StoreDirPerm); err != nil {
		t.Fatalf("MkdirAll(staging directory) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(stageDir, "not-a-batch"), []byte("staging"), fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(staging file) error = %v", err)
	}

	targets, err := RotationTargets(paths, "default", cryptotest.Keyring(t, bytes.Repeat([]byte{0x11}, 32)))
	if err != nil {
		t.Fatalf("RotationTargets() error = %v", err)
	}
	if len(targets) != 0 {
		t.Fatalf("RotationTargets() = %v, want no staging targets", targets)
	}
}

func TestRotationTargetsCleansStaleArtifacts(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	masterKey := bytes.Repeat([]byte{0x22}, 32)
	batch := createRotationTestBatch(t, paths, masterKey)
	metadataPath := paths.RecoveredBatchMetadataPath("default", batch.RestoreID)
	entryPath := filepath.Join(
		paths.RecoveredBatchEntriesDir("default", batch.RestoreID),
		batch.Entries[0].EntryFile,
	)
	writeCopyForRotationTest(t, metadataPath, metadataPath+rotationOldSuffix)
	if err := os.WriteFile(metadataPath+rotationNewSuffix, []byte("uncommitted new key"), fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(metadata .new) error = %v", err)
	}
	writeCopyForRotationTest(t, entryPath, entryPath+rotationOldSuffix)
	if err := os.WriteFile(entryPath+rotationNewSuffix, []byte("uncommitted new key"), fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(entry .new) error = %v", err)
	}

	targets, err := RotationTargets(paths, "default", cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("RotationTargets() error = %v", err)
	}
	if len(targets) != 2 || targets[0].Path != metadataPath || targets[1].Path != entryPath {
		t.Fatalf("RotationTargets() = %v, want metadata and entry", targets)
	}
	assertRotationArtifactsAbsent(t, metadataPath, entryPath)
}

func TestRotationTargetsRestoresCurrentKeyOldArtifacts(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	masterKey := bytes.Repeat([]byte{0x33}, 32)
	batch := createRotationTestBatch(t, paths, masterKey)
	metadataPath := paths.RecoveredBatchMetadataPath("default", batch.RestoreID)
	entryPath := filepath.Join(
		paths.RecoveredBatchEntriesDir("default", batch.RestoreID),
		batch.Entries[0].EntryFile,
	)
	for _, path := range []string{metadataPath, entryPath} {
		if err := os.Rename(path, path+rotationOldSuffix); err != nil {
			t.Fatalf("Rename(%s to .old) error = %v", path, err)
		}
		if err := os.WriteFile(path, []byte("partially swapped new key"), fsutil.StoreFilePerm); err != nil {
			t.Fatalf("WriteFile(partial canonical %s) error = %v", path, err)
		}
		if err := os.WriteFile(path+rotationNewSuffix, []byte("stale pending file"), fsutil.StoreFilePerm); err != nil {
			t.Fatalf("WriteFile(%s.new) error = %v", path, err)
		}
	}

	if _, err := RotationTargets(paths, "default", cryptotest.Keyring(t, masterKey)); err != nil {
		t.Fatalf("RotationTargets() error = %v", err)
	}
	loadedBatch, err := LoadBatch(paths, "default", batch.RestoreID, cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("LoadBatch(reconciled) error = %v", err)
	}
	entry, err := LoadEntry(paths, "default", batch.RestoreID, loadedBatch.Entries[0], cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("LoadEntry(reconciled) error = %v", err)
	}
	entry.ZeroSecrets()
	assertRotationArtifactsAbsent(t, metadataPath, entryPath)
}

func TestRotationTargetsRejectsNonRegularArtifacts(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	masterKey := bytes.Repeat([]byte{0x44}, 32)
	batch := createRotationTestBatch(t, paths, masterKey)
	metadataPath := paths.RecoveredBatchMetadataPath("default", batch.RestoreID)
	if err := os.Symlink(metadataPath, metadataPath+rotationOldSuffix); err != nil {
		t.Fatalf("Symlink(metadata .old) error = %v", err)
	}

	if _, err := RotationTargets(paths, "default", cryptotest.Keyring(t, masterKey)); err == nil {
		t.Fatal("RotationTargets() error = nil, want non-regular artifact rejection")
	}
	if _, err := LoadBatch(paths, "default", batch.RestoreID, cryptotest.Keyring(t, masterKey)); err != nil {
		t.Fatalf("LoadBatch() after rejected reconciliation error = %v", err)
	}
}

func createRotationTestBatch(t *testing.T, paths storepaths.Paths, masterKey []byte) *Batch {
	t.Helper()
	address, keyJSON := keystest.Ed25519KeyJSON(t)
	defer crypto.ZeroBytes(keyJSON)
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
	return batch
}

func writeCopyForRotationTest(t *testing.T, source, destination string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", source, err)
	}
	if err := os.WriteFile(destination, data, fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", destination, err)
	}
}

func assertRotationArtifactsAbsent(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		for _, suffix := range []string{rotationNewSuffix, rotationOldSuffix} {
			if _, err := os.Lstat(path + suffix); !os.IsNotExist(err) {
				t.Fatalf("Lstat(%s) error = %v, want not exist", path+suffix, err)
			}
		}
	}
}
