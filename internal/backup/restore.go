// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

type RestoreLogger func(format string, args ...any)

type ManagedBackupInfo struct {
	Path     string
	FileName string
	// CreatedAt is the archive file's modification time.
	CreatedAt time.Time
	Size      int64
	Checksum  string
}

// BestCreatedAt is the creation time a listing can know without the export
// passphrase: the time in a managed archive's name, else the file time.
// Copying an archive changes its file time; its name keeps the time it was
// created.
func (b ManagedBackupInfo) BestCreatedAt() time.Time {
	if t, ok := ManagedArchiveNameTime(b.FileName); ok {
		return t
	}
	return b.CreatedAt
}

type RestorePreview struct {
	ArchivePath string
	// CreatedAtUnix is the creation time sealed in the authenticated
	// manifest.
	CreatedAtUnix int64
	Keys          []RestoreKeyInfo
	Errors        []RestoreError
}

type RestoreKeyInfo struct {
	StageHint     *RotatingStageHint
	Address       string
	KeyType       string
	AlreadyExists bool
	// HasPolicy reports that the archive carries this key's own policy.
	HasPolicy bool
	Error     string
}

type RestoreError struct {
	Address string
	Error   string
}

// ResolveBackupKeysDir returns the credential directory in an extracted
// credential-backup archive.
func ResolveBackupKeysDir(source string) string {
	return filepath.Join(source, "apb")
}

// PrepareRestoreSource returns an extracted directory for an archive source.
// The caller must invoke cleanup.
func PrepareRestoreSource(source string) (string, func(), error) {
	if !IsArchivePath(source) {
		return source, func() {}, nil
	}
	tmpDir, err := os.MkdirTemp("", "apstore-restore-*")
	if err != nil {
		return "", nil, fmt.Errorf("create archive extraction directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmpDir) }
	if err := ExtractTarGzArchive(source, tmpDir); err != nil {
		cleanup()
		return "", nil, err
	}
	return tmpDir, cleanup, nil
}

func ResolveManagedBackupPath(paths storepaths.Paths, archivePath string) (string, error) {
	return resolveManagedArchivePath(paths.ProductBackupsDir(), archivePath, "backup")
}

func resolveManagedArchivePath(root, archivePath, label string) (string, error) {
	if archivePath == "" {
		return "", fmt.Errorf("%s archive path is required", label)
	}
	if !IsArchivePath(archivePath) {
		return "", fmt.Errorf("%s archive must end in .tar.gz or .tgz: %s", label, archivePath)
	}
	cleanRoot := filepath.Clean(root)
	candidate := archivePath
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(cleanRoot, candidate)
	}
	candidate = filepath.Clean(candidate)
	rel, err := filepath.Rel(cleanRoot, candidate)
	if err != nil {
		return "", fmt.Errorf("validate %s archive path: %w", label, err)
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s archive is outside managed directory", label)
	}
	if strings.Contains(rel, string(filepath.Separator)) {
		return "", fmt.Errorf("%s archive must be a top-level file in the managed directory", label)
	}
	return candidate, nil
}

func ListManagedBackups(paths storepaths.Paths) ([]ManagedBackupInfo, error) {
	dir := paths.ProductBackupsDir()
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read managed backup directory: %w", err)
	}
	backups := make([]ManagedBackupInfo, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !IsArchivePath(entry.Name()) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect backup archive %s: %w", entry.Name(), err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		checksum, size, err := FileSHA256(path)
		if err != nil {
			return nil, fmt.Errorf("checksum backup archive %s: %w", entry.Name(), err)
		}
		backups = append(backups, ManagedBackupInfo{
			Path: path, FileName: entry.Name(), CreatedAt: info.ModTime().UTC(),
			Size: size, Checksum: checksum,
		})
	}
	sort.Slice(backups, func(i, j int) bool {
		a, b := backups[i].BestCreatedAt(), backups[j].BestCreatedAt()
		if !a.Equal(b) {
			return a.After(b)
		}
		return backups[i].FileName < backups[j].FileName
	})
	return backups, nil
}

func DeleteManagedBackup(paths storepaths.Paths, archivePath string) error {
	resolved, err := ResolveManagedBackupPath(paths, archivePath)
	if err != nil {
		return err
	}
	if _, err := StatManagedBackupArchive(resolved); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("backup archive not found: %s", resolved)
		}
		return fmt.Errorf("inspect backup archive: %w", err)
	}
	return fsutil.RemoveDurable(resolved)
}

func StatManagedBackupArchive(archivePath string) (os.FileInfo, error) {
	info, err := os.Lstat(archivePath)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("backup archive must be a regular file: %s", archivePath)
	}
	return info, nil
}

func PreviewRestoreWithNodeRole(
	paths storepaths.Paths,
	archivePath string,
	exportPassphrase []byte,
	role noderole.Role,
) (*RestorePreview, error) {
	resolved, err := ResolveManagedBackupPath(paths, archivePath)
	if err != nil {
		return nil, err
	}
	if _, err := StatManagedBackupArchive(resolved); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("backup archive not found: %s", resolved)
		}
		return nil, fmt.Errorf("inspect backup archive: %w", err)
	}
	sourceRoot, cleanup, err := PrepareRestoreSource(resolved)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	manifest, err := OpenSealedManifest(sourceRoot, exportPassphrase)
	if err != nil {
		return nil, err
	}
	if manifest.SourceNodeRole != string(role) {
		return nil, authenticatedArchiveError(fmt.Errorf("backup source node role %q cannot be restored into %q", manifest.SourceNodeRole, role))
	}
	keysDir := ResolveBackupKeysDir(sourceRoot)
	selectors, err := normalizeCredentialSelectors(keysDir, nil)
	if err != nil {
		return nil, authenticatedArchiveError(err)
	}
	active, err := genstore.ResolveActive(paths)
	if err != nil {
		return nil, authenticatedArchiveError(err)
	}
	preview := &RestorePreview{ArchivePath: resolved, CreatedAtUnix: manifest.CreatedAtUnix}
	for _, selector := range selectors {
		entry, err := inspectCredentialBackupEntry(keysDir, selector, exportPassphrase, role)
		if err == nil {
			err = func() error {
				defer entry.ZeroSecrets()
				if err := validateCredentialRuntimeSupport(&entry); err != nil {
					return err
				}
				_, exists, destinationErr := keys.ManagedCredentialDestinationActive(active, entry.Selector, entry.Category)
				if destinationErr != nil && !isManagedClassConflict(destinationErr) {
					return destinationErr
				}
				info := RestoreKeyInfo{
					Address: selector, KeyType: entry.KeyType,
					StageHint:     validatedRotatingHint(entry, manifest.RotatingStageHints),
					AlreadyExists: exists || destinationErr != nil,
				}
				document, err := readBackupPolicy(keysDir, selector, exportPassphrase, role)
				if err != nil {
					return err
				}
				info.HasPolicy = document != nil
				preview.Keys = append(preview.Keys, info)
				return nil
			}()
		}
		if err != nil {
			preview.Errors = append(preview.Errors, RestoreError{Address: selector, Error: err.Error()})
			preview.Keys = append(preview.Keys, RestoreKeyInfo{Address: selector, Error: err.Error()})
			continue
		}
	}
	return preview, nil
}

// RestoreForRebuild restores one credential-only backup entry, and the
// policy the archive carries for it, into active. It is the offline rebuild
// adapter; live restores use LoadManagedRestoreSet and a generation mint.
func RestoreForRebuild(
	active storepaths.ActivePaths,
	role noderole.Role,
	keysDir, selector string,
	kr *crypto.Keyring,
	exportPassphrase []byte,
	logf RestoreLogger,
) (string, error) {
	entry, err := inspectCredentialBackupEntry(keysDir, selector, exportPassphrase, role)
	if err != nil {
		return "", err
	}
	defer entry.ZeroSecrets()
	if err := validateCredentialRuntimeSupport(&entry); err != nil {
		return "", err
	}
	if err := ApplyCredentialEntry(active, entry, kr, false); err != nil {
		return "", err
	}
	if entry.Policy, err = readBackupPolicy(keysDir, selector, exportPassphrase, role); err != nil {
		return "", err
	}
	if entry.Policy != nil {
		if err := ApplyPolicyEntry(active, role, entry, kr); err != nil {
			return "", fmt.Errorf("restore policy for %s: %w", selector, err)
		}
		if logf != nil {
			logf("restored policy: %s", selector)
		}
	}
	if logf != nil {
		logf("restored credential: %s (%s)", entry.Selector, entry.KeyType)
	}
	return entry.KeyType, nil
}
