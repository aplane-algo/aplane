// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storepass

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// TestDeletedArchiveReleaseCapacity is deliberately opt-in: it writes and
// processes approximately 256 MiB twice to pin the release-layout constants
// to a reproducible capacity result instead of an assumed bound.
func TestDeletedArchiveReleaseCapacity(t *testing.T) {
	if os.Getenv("APLANE_STORE_CAPACITY_TEST") != "1" {
		t.Skip("set APLANE_STORE_CAPACITY_TEST=1 to run the release capacity gate")
	}
	fixture := newRotateFixture(t)
	active, oldKeyring, err := genstore.ResolveStoreRoot(fixture.paths, fixture.oldPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	fillDeletedArchiveWarningLimit(t, active, oldKeyring)
	usage, err := genstore.InspectDeletedArchive(active)
	if err != nil {
		t.Fatal(err)
	}
	if usage.Entries != genstore.DeletedArchiveWarnEntries ||
		usage.EncodedBytes != genstore.DeletedArchiveWarnEncodedBytes {
		t.Fatalf("warning-limit archive = %+v", usage)
	}

	// At the warning threshold, the exact hard-limit reserve remains available
	// for one maximum-sized incident-response deletion.
	candidate := filepath.Join(active.KeysDir(), "EMERGENCY.key")
	if err := os.WriteFile(candidate, make([]byte, crypto.MaxStandaloneEnvelopeBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	prospective, err := genstore.PreflightDeletedArchiveAppend(active, candidate)
	if err != nil {
		t.Fatalf("maximum-sized emergency deletion preflight: %v", err)
	}
	if prospective.Entries != genstore.DeletedArchiveMaxEntries ||
		prospective.EncodedBytes != genstore.DeletedArchiveMaxEncodedBytes {
		t.Fatalf("maximum-sized emergency deletion = %+v", prospective)
	}
	if err := os.Remove(candidate); err != nil {
		t.Fatal(err)
	}

	copyRoot := filepath.Join(t.TempDir(), "archive-copy")
	copyStart := time.Now()
	if err := copyCapacityArchive(active, copyRoot); err != nil {
		t.Fatal(err)
	}
	copyDuration := time.Since(copyStart)
	if err := os.RemoveAll(copyRoot); err != nil {
		t.Fatal(err)
	}

	sealAt := time.Now()
	if err := genstore.WriteSeal(active, sealAt.Unix(), oldKeyring); err != nil {
		t.Fatal(err)
	}
	anchors, err := collectHistoricalAnchors(fixture.paths, active, oldKeyring)
	if err != nil {
		t.Fatal(err)
	}
	successorKeyring, err := crypto.NewSuccessorKeyring(oldKeyring, anchors)
	if err != nil {
		t.Fatal(err)
	}
	scratchRoot := filepath.Join(t.TempDir(), "reencrypted-successor")
	scratch := storepaths.StagedGenerationPaths("gen-1785200001-00000002", scratchRoot)
	for _, dir := range []string{
		scratch.KeysDir(), scratch.KeyTypeRecordsDir(), scratch.DeletedKeysDir(),
		scratch.DeletedKeyTypeRecordsDir(),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	reencryptStart := time.Now()
	if _, err := reencryptSealedGeneration(
		fixture.paths, active, scratch, oldKeyring, successorKeyring, sealAt,
	); err != nil {
		t.Fatal(err)
	}
	reencryptDuration := time.Since(reencryptStart)
	successorKeyring.Zero()
	oldKeyring.Zero()
	if err := os.RemoveAll(scratchRoot); err != nil {
		t.Fatal(err)
	}

	newPassphrase := []byte("capacity-test-new-passphrase")
	changepassStart := time.Now()
	if _, err := Rotate(fixture.paths, fixture.oldPassphrase, newPassphrase, RotateOptions{}); err != nil {
		t.Fatal(err)
	}
	changepassDuration := time.Since(changepassStart)
	selected, selectedKeyring, err := genstore.ResolveStoreRoot(fixture.paths, newPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	selectedKeyring.Zero()
	selectedUsage, err := genstore.InspectDeletedArchive(selected)
	if err != nil {
		t.Fatal(err)
	}
	if selectedUsage != usage {
		t.Fatalf("changepass archive usage = %+v, want %+v", selectedUsage, usage)
	}
	sealInfo, err := os.Stat(active.SealPath())
	if err != nil {
		t.Fatal(err)
	}
	retainedBytes, err := regularFileBytes(fixture.paths.GenerationsDir())
	if err != nil {
		t.Fatal(err)
	}
	if retainedBytes < 2*usage.EncodedBytes {
		t.Fatalf("retained disk bytes = %d, want at least two archive copies", retainedBytes)
	}

	t.Logf(
		"deleted archive release capacity: entries=%d encoded_bytes=%d copy_time=%s reencrypt_time=%s changepass_time=%s seal_bytes=%d retained_disk_bytes=%d",
		usage.Entries,
		usage.EncodedBytes,
		copyDuration,
		reencryptDuration,
		changepassDuration,
		sealInfo.Size(),
		retainedBytes,
	)
}

func fillDeletedArchiveWarningLimit(t *testing.T, active storepaths.GenPaths, kr *crypto.Keyring) {
	t.Helper()
	usage, err := genstore.InspectDeletedArchive(active)
	if err != nil {
		t.Fatal(err)
	}
	remaining := genstore.DeletedArchiveWarnEntries - usage.Entries
	if remaining < 1 {
		t.Fatalf("fixture leaves no capacity entries: %+v", usage)
	}
	payload := bytes.Repeat([]byte{'x'}, 48_800)
	for i := 0; i < remaining-1; i++ {
		selector := fmt.Sprintf("CAPACITY-%04d", i)
		sealed, err := kr.Seal(payload, crypto.AccountKeyContext(selector))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(active.DeletedKeysDir(), selector+".key"), sealed, 0o600); err != nil {
			t.Fatal(err)
		}
		usage.Entries++
		usage.EncodedBytes += int64(len(sealed))
	}
	fillerBytes := genstore.DeletedArchiveWarnEncodedBytes - usage.EncodedBytes
	if fillerBytes <= 2 || fillerBytes > crypto.MaxStandaloneEnvelopeBytes {
		t.Fatalf("capacity filler size = %d", fillerBytes)
	}
	// Public witness metadata is plaintext generation state. JSON whitespace
	// lets the fixture hit the exact byte limit without weakening envelope
	// parsing or depending on base64 length quanta.
	filler := make([]byte, fillerBytes)
	copy(filler, []byte("{}"))
	for i := 2; i < len(filler); i++ {
		filler[i] = ' '
	}
	if err := os.WriteFile(filepath.Join(active.DeletedKeysDir(), "CAPACITY-FILLER.wit.json"), filler, 0o600); err != nil {
		t.Fatal(err)
	}
}

func copyCapacityArchive(active storepaths.GenPaths, destination string) error {
	for _, item := range []struct {
		source string
		name   string
	}{
		{active.DeletedKeysDir(), "keys"},
		{active.DeletedKeyTypeRecordsDir(), "keytypes"},
	} {
		target := filepath.Join(destination, item.name)
		if err := os.MkdirAll(target, 0o700); err != nil {
			return err
		}
		entries, err := os.ReadDir(item.source)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			in, err := os.Open(filepath.Join(item.source, entry.Name()))
			if err != nil {
				return err
			}
			out, err := os.OpenFile(filepath.Join(target, entry.Name()), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				_ = in.Close()
				return err
			}
			_, copyErr := io.Copy(out, in)
			closeInErr := in.Close()
			closeOutErr := out.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeInErr != nil {
				return closeInErr
			}
			if closeOutErr != nil {
				return closeOutErr
			}
		}
	}
	return nil
}

func regularFileBytes(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	return total, err
}
