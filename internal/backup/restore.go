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
	Path      string
	FileName  string
	CreatedAt time.Time
	Size      int64
	Checksum  string
}

type RestorePreview struct {
	ArchivePath string
	Keys        []RestoreKeyInfo
	Errors      []RestoreError
}

type RestoreKeyInfo struct {
	Address       string
	KeyType       string
	AlreadyExists bool
	Error         string
}

type RestoreError struct {
	Address string
	Error   string
}

// Restorer is the narrow offline/rebuild adapter for credential-only backup
// entries. Live restores use LoadManagedRestoreSet and a generation mint.
type Restorer struct {
	Paths          storepaths.Paths
	IdentityID     string
	NodeRole       noderole.Role
	Overwrite      bool
	Logf           RestoreLogger
	ActiveOverride storepaths.ActivePaths
}

func NewRestorer(paths storepaths.Paths, identityID string) Restorer {
	return Restorer{Paths: paths, IdentityID: identityID}
}

func (r Restorer) WithLogger(logf RestoreLogger) Restorer {
	r.Logf = logf
	return r
}

func (r Restorer) WithNodeRole(role noderole.Role) Restorer {
	r.NodeRole = role
	return r
}

func (r Restorer) WithActiveNamespace(active storepaths.ActivePaths) Restorer {
	r.ActiveOverride = active
	return r
}

func (r Restorer) WithOverwrite(overwrite bool) Restorer {
	r.Overwrite = overwrite
	return r
}

func (r Restorer) nodeRole() noderole.Role {
	if r.NodeRole == "" {
		return noderole.DefaultRole()
	}
	return r.NodeRole
}

func (r Restorer) activeNamespace() (storepaths.ActivePaths, error) {
	if r.ActiveOverride != nil {
		return r.ActiveOverride, nil
	}
	return genstore.ResolveActive(r.Paths, r.IdentityID)
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

func ResolveManagedBackupPath(paths storepaths.Paths, identityID, archivePath string) (string, error) {
	return resolveManagedArchivePath(paths.IdentityBackupsDir(identityID), archivePath, "backup")
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

func ListManagedBackups(paths storepaths.Paths, identityID string) ([]ManagedBackupInfo, error) {
	dir := paths.IdentityBackupsDir(identityID)
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
	sort.Slice(backups, func(i, j int) bool { return backups[i].CreatedAt.After(backups[j].CreatedAt) })
	return backups, nil
}

func DeleteManagedBackup(paths storepaths.Paths, identityID, archivePath string) error {
	resolved, err := ResolveManagedBackupPath(paths, identityID, archivePath)
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
	identityID, archivePath string,
	exportPassphrase []byte,
	role noderole.Role,
) (*RestorePreview, error) {
	resolved, err := ResolveManagedBackupPath(paths, identityID, archivePath)
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
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		return nil, authenticatedArchiveError(err)
	}
	preview := &RestorePreview{ArchivePath: resolved}
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
				preview.Keys = append(preview.Keys, RestoreKeyInfo{
					Address: selector, KeyType: entry.KeyType,
					AlreadyExists: exists || destinationErr != nil,
				})
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

func (r Restorer) RestoreKey(keysDir, selector string, kr *crypto.Keyring, exportPassphrase []byte) (string, error) {
	entry, err := inspectCredentialBackupEntry(keysDir, selector, exportPassphrase, r.nodeRole())
	if err != nil {
		return "", err
	}
	defer entry.ZeroSecrets()
	if err := validateCredentialRuntimeSupport(&entry); err != nil {
		return "", err
	}
	active, err := r.activeNamespace()
	if err != nil {
		return "", err
	}
	if err := ApplyCredentialEntry(active, entry, kr, r.Overwrite); err != nil {
		return "", err
	}
	if r.Logf != nil {
		r.Logf("restored credential: %s (%s)", entry.Selector, entry.KeyType)
	}
	return entry.KeyType, nil
}

func (r Restorer) RestoreActiveForRebuild(keysDir, selector string, kr *crypto.Keyring, exportPassphrase []byte) (string, error) {
	return r.RestoreKey(keysDir, selector, kr, exportPassphrase)
}

// RestoreKeyMetadata reads the canonical identity fields used by offline
// restore validation.
func RestoreKeyMetadata(keyJSON []byte) (keyType, selector string, hasLogicSigBytecode bool, err error) {
	payload, err := keys.ParsePayload(keyJSON)
	if err != nil {
		return "", "", false, fmt.Errorf("parse credential: %w", err)
	}
	defer payload.ZeroSecrets()
	selector, err = payload.Selector()
	if err != nil {
		return "", "", false, err
	}
	return payload.KeyType, selector, len(payload.LogicSigBytecode) > 0, nil
}
