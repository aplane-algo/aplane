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
	KeyCount        int
	Addresses       []string
	Verified        bool
	// Warning reports a published archive whose directory entry could not
	// be made durable.
	Warning string
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
// When Addresses is empty, all active keys are exported. A selection that
// names an address twice is refused before anything is written.
func CreateKeysArchive(req CreateKeysArchiveRequest) (*ArchiveResult, error) {
	var selected []string
	if len(req.Addresses) > 0 {
		var err error
		if selected, err = selectedBackupAddresses(req.Addresses); err != nil {
			return nil, err
		}
	}
	if err := prepareManagedArchiveDestination(req.Paths, req.ArchivePath); err != nil {
		return nil, err
	}

	stageDir, err := os.MkdirTemp("", "aplane-backup-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create backup staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(stageDir) }()

	// Export sources resolve through the active layout once per archive.
	activeStore, err := genstore.Resolve(req.Paths)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve active key store layout: %w", err)
	}

	exported, err := exportCredentials(
		activeStore.KeysDir(),
		filepath.Join(stageDir, "apb"),
		selected,
		req.Keyring,
		req.ExportPassphrase,
	)
	if err != nil {
		return nil, err
	}
	nodeRole, _, err := noderole.Load(req.Paths)
	if err != nil {
		return nil, fmt.Errorf("failed to load source node role: %w", err)
	}
	if _, err := exportKeyPolicies(activeStore, nodeRole.Role, stageDir, exported, req.Keyring, req.ExportPassphrase); err != nil {
		return nil, err
	}
	if _, err := exportKeySourceTokens(activeStore, nodeRole.Role, stageDir, exported, req.Keyring, req.ExportPassphrase); err != nil {
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
	published, err := publishVerifiedArchive(stageDir, req.ArchivePath, req.ExportPassphrase)
	if err != nil {
		return nil, err
	}

	return &ArchiveResult{
		ArchivePath:     req.ArchivePath,
		ArchiveChecksum: published.checksum,
		ArchiveSize:     published.size,
		KeyCount:        len(exported),
		Addresses:       exported,
		Verified:        true,
		Warning:         published.warning,
	}, nil
}

// selectedBackupAddresses is the selection a selected-keys backup exports, in
// request order and without the empty entries a caller may pass. It refuses
// an address named twice, which would be exported and counted twice, as
// restore refuses a duplicate selector.
func selectedBackupAddresses(addresses []string) ([]string, error) {
	selected := make([]string, 0, len(addresses))
	seen := make(map[string]bool, len(addresses))
	for _, address := range addresses {
		if address == "" {
			continue
		}
		if seen[address] {
			return nil, fmt.Errorf("duplicate backup address %q", address)
		}
		seen[address] = true
		selected = append(selected, address)
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no addresses selected for backup")
	}
	return selected, nil
}

// PartialArchiveSuffix marks an archive still being written or verified.
// The managed listing takes only .tar.gz and .tgz names, so a partial archive
// is never listed as a backup; the daemon's startup sweep removes one a crash
// left behind.
const PartialArchiveSuffix = ".partial"

// CreateValidationPrefix names the directory a new archive is extracted into
// to verify it, inside the managed backup directory so the startup sweep
// removes one a crash left behind.
const CreateValidationPrefix = ".create-validation-"

// beforeArchivePublish, when a test sets it, runs on the verified partial
// archive just before it is renamed into place.
var beforeArchivePublish func(partial string) error

// publishedArchive is an archive given its managed name: its checksum and
// size, and a warning when the directory entry could not be made durable.
type publishedArchive struct {
	checksum string
	size     int64
	warning  string
}

// publishVerifiedArchive packages stageDir as the archive at archivePath. It
// writes and syncs the archive under a partial name beside it, verifies the
// archive by extracting it and opening every credential and the sealed
// manifest with the export passphrase, and only then renames it to its
// managed name and syncs the directory. The caller holds the store mutation
// lock, which every backup create and import takes, so the managed name it
// found free is still free when it renames. Any failure before the rename
// leaves nothing under either name. A directory sync that fails after it
// leaves the complete, verified archive published, with a warning, as an
// import does.
func publishVerifiedArchive(stageDir, archivePath string, passphrase []byte) (publishedArchive, error) {
	if _, err := os.Lstat(archivePath); err == nil {
		return publishedArchive{}, fmt.Errorf("archive already exists: %s", archivePath)
	} else if !os.IsNotExist(err) {
		return publishedArchive{}, err
	}
	dir := filepath.Dir(archivePath)
	partial := archivePath + PartialArchiveSuffix
	// Only this function writes partial names, under the store mutation
	// lock, so one already there is an earlier attempt's leftover.
	_ = os.Remove(partial)
	defer func() { _ = os.Remove(partial) }()
	if err := CreateTarGzArchive(stageDir, partial); err != nil {
		return publishedArchive{}, err
	}
	if err := os.Chmod(partial, fsutil.StoreFilePerm); err != nil {
		return publishedArchive{}, fmt.Errorf("failed to set backup archive permissions: %w", err)
	}

	verifyDir, err := os.MkdirTemp(dir, CreateValidationPrefix+"*")
	if err != nil {
		return publishedArchive{}, fmt.Errorf("failed to create backup verification directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(verifyDir) }()
	if err := ExtractTarGzArchive(partial, verifyDir); err != nil {
		return publishedArchive{}, fmt.Errorf("failed to verify backup archive: %w", err)
	}
	verifyReport, err := DeepVerifyBackupBytes(verifyDir, passphrase)
	if err != nil {
		return publishedArchive{}, fmt.Errorf("failed to verify backup archive: %w", err)
	}
	if err := verifyReport.Incomplete(); err != nil {
		return publishedArchive{}, fmt.Errorf("failed to verify backup archive: %w", err)
	}
	checksum, size, err := FileSHA256(partial)
	if err != nil {
		return publishedArchive{}, fmt.Errorf("failed to checksum backup archive: %w", err)
	}
	if beforeArchivePublish != nil {
		if err := beforeArchivePublish(partial); err != nil {
			return publishedArchive{}, err
		}
	}

	if err := os.Rename(partial, archivePath); err != nil {
		return publishedArchive{}, fmt.Errorf("failed to publish backup archive: %w", err)
	}
	published := publishedArchive{checksum: checksum, size: size}
	if err := fsutil.SyncDir(dir); err != nil {
		published.warning = fmt.Sprintf("backup archive was published but directory durability could not be confirmed: %v", err)
	}
	return published, nil
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
// carries (aplane-backup-YYYYMMDD-HHMMSS.nnnnnnnnn.tar.gz), in UTC. Names
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
	t, err := time.ParseInLocation(ManagedArchiveTimestampLayout, stamp, time.UTC)
	return t, err == nil
}
