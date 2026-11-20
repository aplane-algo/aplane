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
	// Keys lists the credentials this node admits; Skipped those it does
	// not, with the reason.
	Keys    []RestoreKeyInfo
	Skipped []SkippedEntry
}

type RestoreKeyInfo struct {
	StageHint     *RotatingStageHint
	Address       string
	KeyType       string
	AlreadyExists bool
	// HasPolicy reports that the archive carries this key's own policy.
	HasPolicy bool
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
		return "", nil, withArchivePaths(tmpDir, err)
	}
	return tmpDir, cleanup, nil
}

// archivePathError is an error about an extracted archive whose text names
// each file by its path in the archive, never by where it was extracted: an
// error reaches the operator and the audit log, and the extraction
// directory is the daemon's.
type archivePathError struct {
	root string
	err  error
}

func (e *archivePathError) Error() string {
	text := strings.ReplaceAll(e.err.Error(), e.root+string(filepath.Separator), "")
	return strings.ReplaceAll(text, e.root, ".")
}

func (e *archivePathError) Unwrap() error { return e.err }

// withArchivePaths names the files under root in err's text by their paths
// in the archive extracted there.
func withArchivePaths(root string, err error) error {
	if err == nil {
		return nil
	}
	return &archivePathError{root: filepath.Clean(root), err: err}
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

// PreviewRestoreWithNodeRole admits every credential of a managed archive as
// a whole-archive restore would, and reports each with its destination
// presence, or as skipped with the reason. It mutates nothing. An archive
// with nothing to restore still previews, so every reason is shown; restore
// refuses it.
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
	archive, err := openArchive(sourceRoot, exportPassphrase)
	if err != nil {
		return nil, err
	}
	if err := archive.requireSourceRole(role); err != nil {
		return nil, err
	}
	active, err := genstore.Resolve(paths)
	if err != nil {
		return nil, authenticatedArchiveError(err)
	}
	preview := &RestorePreview{ArchivePath: resolved, CreatedAtUnix: archive.manifest.CreatedAtUnix}
	preview.Skipped, err = archive.admitEach(archive.selectors, exportPassphrase, role, func(entry CredentialEntry) error {
		defer entry.ZeroSecrets()
		_, exists, destinationErr := keys.ManagedCredentialDestinationActive(active, entry.Selector(), entry.Category())
		if destinationErr != nil && !isManagedClassConflict(destinationErr) {
			return destinationErr
		}
		preview.Keys = append(preview.Keys, RestoreKeyInfo{
			Address: entry.Selector(), KeyType: entry.KeyType(), StageHint: entry.StageHint,
			AlreadyExists: exists || destinationErr != nil, HasPolicy: entry.Policy != nil,
		})
		return nil
	})
	if err != nil {
		return nil, authenticatedArchiveError(err)
	}
	return preview, nil
}

// ApplyRebuildSet installs every entry of set, with its archived policy, into
// the staged first generation of a fresh store of role. It is the offline
// rebuild's apply step; a live restore classifies its set against the
// destination and applies it inside a generation mint.
func ApplyRebuildSet(staged storepaths.GenPaths, role noderole.Role, set *RestoreSet, kr *crypto.Keyring) error {
	for i := range set.Entries {
		entry := set.Entries[i]
		if err := ApplyCredentialEntry(staged, entry, kr, false); err != nil {
			return fmt.Errorf("rebuild %s: %w", entry.Selector(), err)
		}
		if entry.Policy != nil {
			if err := ApplyPolicyEntry(staged, role, entry, kr); err != nil {
				return fmt.Errorf("restore policy for %s: %w", entry.Selector(), err)
			}
		}
	}
	return nil
}
