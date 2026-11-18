// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

type ArchiveResult struct {
	ArchivePath     string
	ArchiveChecksum string
	ArchiveSize     int64
	Checksums       map[string]string
	KeyCount        int
	Addresses       []string
	Verified        bool
}

// CreateKeysArchiveRequest contains one managed backup creation snapshot.
// Keyring and ExportPassphrase are borrowed for the duration of the call and
// are not cleared.
type CreateKeysArchiveRequest struct {
	RotatingStageHints map[string]RotatingStageHint
	Paths              storepaths.Paths
	ArchivePath        string
	Addresses          []string
	Keyring            *crypto.Keyring
	ExportPassphrase   []byte
}

// CreateKeysArchive exports selected active keys into one tar.gz/tgz archive.
// When Addresses is empty, all active keys are exported.
func CreateKeysArchive(req CreateKeysArchiveRequest) (*ArchiveResult, error) {
	if err := prepareManagedArchiveDestination(req.Paths, req.ArchivePath); err != nil {
		return nil, err
	}

	stageDir, err := os.MkdirTemp("", "aplane-backup-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create backup staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(stageDir) }()

	// Export sources resolve through the active layout once per archive.
	activeStore, err := genstore.ResolveActive(req.Paths)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve active key store layout: %w", err)
	}
	activeKeysDir := activeStore.KeysDir()

	keysDestDir := filepath.Join(stageDir, "apb")
	checksums := make(map[string]string)
	var exported []string
	if len(req.Addresses) == 0 {
		var err error
		checksums, err = ExportAllKeys(
			activeKeysDir,
			stageDir,
			req.Keyring,
			req.ExportPassphrase,
		)
		if err != nil {
			return nil, err
		}
		exported, err = ScanBackupFiles(keysDestDir)
		if err != nil {
			return nil, err
		}
	} else {
		if err := os.MkdirAll(keysDestDir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create backup keys directory: %w", err)
		}
		for _, address := range req.Addresses {
			if address == "" {
				continue
			}
			checksum, _, err := ExportKey(
				activeKeysDir,
				keysDestDir,
				address,
				req.Keyring,
				req.ExportPassphrase,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to export %s: %w", address, err)
			}
			checksums[address] = checksum
			exported = append(exported, address)
		}
		if len(exported) == 0 {
			return nil, fmt.Errorf("no addresses selected for backup")
		}
	}
	nodeRole, _, err := noderole.Load(req.Paths)
	if err != nil {
		return nil, fmt.Errorf("failed to load source node role: %w", err)
	}
	if _, err := exportKeyPolicies(activeStore, nodeRole.Role, stageDir, exported, req.Keyring, req.ExportPassphrase); err != nil {
		return nil, err
	}
	if err := WriteReadme(stageDir); err != nil {
		return nil, err
	}
	// Last: the manifest inventories every member written above, so it can
	// only be sealed once they are final.
	selectedHints := make(map[string]RotatingStageHint)
	for _, selector := range exported {
		if h, ok := req.RotatingStageHints[selector]; ok {
			selectedHints[selector] = h
		}
	}
	if err := WriteSealedManifest(
		stageDir,
		nodeRole.Role,
		time.Now(),
		req.ExportPassphrase,
		selectedHints,
	); err != nil {
		return nil, err
	}
	if err := requireExtractableArchive(stageDir); err != nil {
		return nil, err
	}
	if err := publishVerifiedArchive(stageDir, req.ArchivePath, req.ExportPassphrase); err != nil {
		return nil, err
	}
	archiveChecksum, archiveSize, err := FileSHA256(req.ArchivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to checksum backup archive: %w", err)
	}

	return &ArchiveResult{
		ArchivePath:     req.ArchivePath,
		ArchiveChecksum: archiveChecksum,
		ArchiveSize:     archiveSize,
		Checksums:       checksums,
		KeyCount:        len(exported),
		Addresses:       exported,
		Verified:        true,
	}, nil
}

// partialArchiveSuffix marks an archive still being written or verified.
// The managed listing takes only .tar.gz and .tgz names, so a partial archive
// is never listed as a backup, even one a crash left behind.
const partialArchiveSuffix = ".partial"

// publishVerifiedArchive packages stageDir as the archive at archivePath. It
// writes and syncs the archive under a partial name beside it, verifies the
// archive by extracting it and opening every credential and the sealed
// manifest with the export passphrase, and only then gives it its managed
// name, which it never takes from an existing file, and syncs the directory.
// On any failure nothing is left under either name.
func publishVerifiedArchive(stageDir, archivePath string, passphrase []byte) (err error) {
	partial := archivePath + partialArchiveSuffix
	// Only this function writes partial names, under the store mutation
	// lock, so one already there is an earlier attempt's leftover.
	_ = os.Remove(partial)
	defer func() { _ = os.Remove(partial) }()
	if err := CreateTarGzArchive(stageDir, partial); err != nil {
		return err
	}
	if err := os.Chmod(partial, fsutil.StoreFilePerm); err != nil {
		return fmt.Errorf("failed to set backup archive permissions: %w", err)
	}

	verifyDir, err := os.MkdirTemp("", "aplane-backup-verify-*")
	if err != nil {
		return fmt.Errorf("failed to create backup verification directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(verifyDir) }()
	if err := ExtractTarGzArchive(partial, verifyDir); err != nil {
		return fmt.Errorf("failed to verify backup archive: %w", err)
	}
	verifyReport, err := DeepVerifyBackupBytes(verifyDir, passphrase)
	if err != nil {
		return fmt.Errorf("failed to verify backup archive: %w", err)
	}
	if verifyReport.FailedFiles > 0 {
		return fmt.Errorf("failed to verify backup archive: %d file(s) failed verification", verifyReport.FailedFiles)
	}

	// A hard link publishes the synced, verified file under its managed name
	// and fails rather than replace one that exists.
	if err := os.Link(partial, archivePath); err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("archive already exists: %s", archivePath)
		}
		return fmt.Errorf("failed to publish backup archive: %w", err)
	}
	if err := fsutil.SyncDir(filepath.Dir(archivePath)); err != nil {
		_ = os.Remove(archivePath)
		return fmt.Errorf("failed to make backup archive durable: %w", err)
	}
	return nil
}

// FileSHA256 returns the SHA-256 checksum and size of path.
func FileSHA256(path string) (string, int64, error) {
	return fsutil.RegularFileSHA256(path)
}

func prepareManagedArchiveDestination(paths storepaths.Paths, archivePath string) error {
	for _, dir := range []string{
		paths.BackupsRootDir(),
		paths.ProductBackupsDir(),
		filepath.Dir(archivePath),
	} {
		if err := ensureStoreDir(dir); err != nil {
			return err
		}
	}
	return nil
}

func ensureStoreDir(path string) error {
	if err := os.MkdirAll(path, fsutil.StoreDirPerm); err != nil {
		return fmt.Errorf("failed to create backup directory %s: %w", path, err)
	}
	if err := os.Chmod(path, fsutil.StoreDirPerm); err != nil {
		return fmt.Errorf("failed to set backup directory permissions for %s: %w", path, err)
	}
	return nil
}

// ManagedArchiveTimestampLayout is the UTC time in a managed archive's name.
const ManagedArchiveTimestampLayout = "20060102-150405.000000000"

const (
	managedArchivePrefix = "aplane-backup-"
	managedArchiveSuffix = ".tar.gz"
)

func BuildManagedArchivePath(paths storepaths.Paths, ts string) string {
	fileName := managedArchivePrefix + ts + managedArchiveSuffix
	return filepath.Join(paths.ProductBackupsDir(), fileName)
}

// ManagedArchiveNameTime is the creation time a managed archive's name
// carries (aplane-backup-YYYYMMDD-HHMMSS[.nnnnnnnnn].tar.gz), in UTC. Names
// are not authenticated; ok is false for any other name.
func ManagedArchiveNameTime(fileName string) (time.Time, bool) {
	stamp, found := strings.CutPrefix(fileName, managedArchivePrefix)
	if !found {
		return time.Time{}, false
	}
	stamp, found = strings.CutSuffix(stamp, managedArchiveSuffix)
	if !found {
		return time.Time{}, false
	}
	for _, layout := range []string{ManagedArchiveTimestampLayout, "20060102-150405"} {
		if t, err := time.ParseInLocation(layout, stamp, time.UTC); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
